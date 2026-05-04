//! PKCS#11 v2.40 / v3.1 RNG-only provider.
//!
//! One slot per RNG-pool view is published at `C_Initialize` time. The token
//! announces RNG support to applications via the `CKF_RNG` token-info flag
//! (set unconditionally in `C_GetTokenInfo`); `C_GenerateRandom` is the only
//! crypto entrypoint backed by real device work and the only thing the token
//! claims to do. Everything else is bookkeeping or
//! [`CKR_FUNCTION_NOT_SUPPORTED`]. PKCS#11 has no standard `CKM_*` for the
//! RNG, so `C_GetMechanismList` is intentionally empty — `CKF_RNG` is the
//! sole, canonical advertisement.
//!
//! The module exposes two interfaces via the v3 discovery API
//! (`C_GetInterfaceList` / `C_GetInterface`):
//!   - `"PKCS 11"` v3.1 — the modern interface, backed by
//!     [`CK_FUNCTION_LIST_3_0`] (the 3.x ABI; 3.1 adds no new entries).
//!   - `"PKCS 11"` v2.40 — the legacy interface, backed by
//!     [`CK_FUNCTION_LIST`], identical to what `C_GetFunctionList` returns.
//!
//! Threading: spec compliance against concurrent calls from app threads is
//! provided by a single global mutex around all state mutations, including
//! the per-card APDU exchange — which serializes the underlying card anyway.

#![allow(non_upper_case_globals, non_snake_case, non_camel_case_types)]

use std::ffi::{c_void, CStr};
use std::os::raw::c_char;
use std::sync::{Mutex, MutexGuard, OnceLock};

use cryptoki_sys::*;
use p11rand_core::pool::{self, Config as PoolConfig, Pool};

mod config {
    include!(concat!(env!("OUT_DIR"), "/config.rs"));
}

const LIB_DESC: &[u8] = b"mini-pkcs11-rand RNG provider";
const LIB_MFR: &[u8] = b"mini-pkcs11-rand";
const MAX_SESSIONS: usize = 64;

const POOL_CFG: PoolConfig = PoolConfig {
    iso7816_cards: config::ISO7816_CARDS,
    infnoise_devices: config::INFNOISE_DEVICES,
    iso7816_input_bytes: config::ISO7816_INPUT_BYTES,
    infnoise_input_bytes: config::INFNOISE_INPUT_BYTES,
};

struct Module {
    initialized: bool,
    slots: Vec<SlotState>,
    sessions: Vec<Option<Session>>,
}

struct SlotState {
    name: String,
    token_present: bool,
}

struct Session {
    slot: CK_SLOT_ID,
    flags: CK_FLAGS,
    pool: Pool,
}

fn module() -> &'static Mutex<Module> {
    static M: OnceLock<Mutex<Module>> = OnceLock::new();
    M.get_or_init(|| {
        Mutex::new(Module {
            initialized: false,
            slots: Vec::new(),
            sessions: (0..MAX_SESSIONS).map(|_| None).collect(),
        })
    })
}

/// Pad a fixed-width PKCS#11 string field with spaces (PKCS#11 strings are
/// space-padded, NOT null-terminated).
fn pad_field(dst: &mut [u8], src: &[u8]) {
    let n = src.len().min(dst.len());
    dst[..n].copy_from_slice(&src[..n]);
    if n < dst.len() {
        dst[n..].fill(b' ');
    }
}

fn refresh_slot(m: &mut Module, i: usize) -> bool {
    // Probe by reading the live "is the pool fillable" answer; the exact
    // slot identity doesn't matter because we only ever publish the one
    // pool view.
    let present = pool::fillable(&POOL_CFG).unwrap_or(false);
    m.slots[i].token_present = present;
    present
}

fn lock<'a>() -> MutexGuard<'a, Module> {
    module().lock().expect("module mutex poisoned")
}

fn find_session(m: &Module, h: CK_SESSION_HANDLE) -> Option<usize> {
    if h == 0 {
        return None;
    }
    let idx = (h as usize).checked_sub(1)?;
    if idx < m.sessions.len() && m.sessions[idx].is_some() {
        Some(idx)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Initialization / finalization
// ---------------------------------------------------------------------------

unsafe extern "C" fn C_Initialize(p_init_args: CK_VOID_PTR) -> CK_RV {
    let mut m = lock();
    if m.initialized {
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }
    if !p_init_args.is_null() {
        let a = unsafe { &*(p_init_args as *const CK_C_INITIALIZE_ARGS) };
        if !a.pReserved.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        // We are thread-safe with our own mutex; OS_LOCKING_OK is fine and
        // app-supplied locking primitives are accepted but ignored.
    }

    if pool::global_init(&POOL_CFG).is_err() {
        return CKR_FUNCTION_FAILED;
    }

    // We publish exactly one slot — the pool view — when it can currently
    // be filled. The slot's `name` is informational only.
    let fillable = match pool::fillable(&POOL_CFG) {
        Ok(b) => b,
        Err(_) => {
            pool::global_shutdown(&POOL_CFG);
            return CKR_FUNCTION_FAILED;
        }
    };

    let mut slots = Vec::new();
    if fillable {
        slots.push(SlotState {
            name: POOL_CFG.slot_name(),
            token_present: true,
        });
    } else {
        // Even when not fillable right now, publish the slot so apps can
        // poll C_GetSlotInfo and see CKF_TOKEN_PRESENT come up later. This
        // matches the C implementation's behavior — it always publishes
        // POOL_SIZE-derived slots regardless of live presence.
        slots.push(SlotState {
            name: POOL_CFG.slot_name(),
            token_present: false,
        });
    }
    m.slots = slots;

    for s in m.sessions.iter_mut() {
        *s = None;
    }
    m.initialized = true;
    CKR_OK
}

unsafe extern "C" fn C_Finalize(p_reserved: CK_VOID_PTR) -> CK_RV {
    if !p_reserved.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut m = lock();
    if !m.initialized {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    for s in m.sessions.iter_mut() {
        *s = None;
    }
    m.slots.clear();
    pool::global_shutdown(&POOL_CFG);
    m.initialized = false;
    CKR_OK
}

unsafe extern "C" fn C_GetInfo(p_info: CK_INFO_PTR) -> CK_RV {
    if p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    {
        let m = lock();
        if !m.initialized {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
    }
    let info = unsafe { &mut *p_info };
    // Advertise 3.1 as the highest spec we implement. The v2.40 ABI is still
    // discoverable via C_GetFunctionList / the "PKCS 11" v2.40 interface.
    *info = CK_INFO {
        cryptokiVersion: CK_VERSION { major: 3, minor: 1 },
        manufacturerID: [0; 32],
        flags: 0,
        libraryDescription: [0; 32],
        libraryVersion: CK_VERSION { major: 0, minor: 1 },
    };
    pad_field(&mut info.manufacturerID, LIB_MFR);
    pad_field(&mut info.libraryDescription, LIB_DESC);
    CKR_OK
}

// ---------------------------------------------------------------------------
// Slots / tokens
// ---------------------------------------------------------------------------

unsafe extern "C" fn C_GetSlotList(
    token_present: CK_BBOOL,
    p_list: CK_SLOT_ID_PTR,
    p_count: CK_ULONG_PTR,
) -> CK_RV {
    if p_count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut m = lock();
    if !m.initialized {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    // When the caller filters on token_present, refresh each slot so the
    // answer reflects the live state. Without the filter, we just enumerate
    // all slots — IDs are stable across calls.
    let filter = token_present == CK_TRUE;
    let mut want = 0usize;
    let n = m.slots.len();
    for i in 0..n {
        if filter && !refresh_slot(&mut m, i) {
            continue;
        }
        want += 1;
    }

    let count = unsafe { &mut *p_count };
    if p_list.is_null() {
        *count = want as CK_ULONG;
        return CKR_OK;
    }
    if (*count as usize) < want {
        *count = want as CK_ULONG;
        return CKR_BUFFER_TOO_SMALL;
    }

    let mut out = 0usize;
    for i in 0..n {
        if filter && !m.slots[i].token_present {
            continue;
        }
        unsafe { *p_list.add(out) = i as CK_SLOT_ID };
        out += 1;
    }
    *count = out as CK_ULONG;
    CKR_OK
}

unsafe extern "C" fn C_GetSlotInfo(slot: CK_SLOT_ID, p_info: CK_SLOT_INFO_PTR) -> CK_RV {
    if p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut m = lock();
    if !m.initialized {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    let i = slot as usize;
    if i >= m.slots.len() {
        return CKR_SLOT_ID_INVALID;
    }
    let present = refresh_slot(&mut m, i);
    let name = m.slots[i].name.clone();
    drop(m);

    let info = unsafe { &mut *p_info };
    *info = CK_SLOT_INFO {
        slotDescription: [0; 64],
        manufacturerID: [0; 32],
        flags: CKF_HW_SLOT
            | CKF_REMOVABLE_DEVICE
            | if present { CKF_TOKEN_PRESENT } else { 0 },
        hardwareVersion: CK_VERSION { major: 0, minor: 1 },
        firmwareVersion: CK_VERSION { major: 0, minor: 1 },
    };
    pad_field(&mut info.slotDescription, name.as_bytes());
    pad_field(&mut info.manufacturerID, LIB_MFR);
    CKR_OK
}

unsafe extern "C" fn C_GetTokenInfo(slot: CK_SLOT_ID, p_info: CK_TOKEN_INFO_PTR) -> CK_RV {
    if p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut m = lock();
    if !m.initialized {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    let i = slot as usize;
    if i >= m.slots.len() {
        return CKR_SLOT_ID_INVALID;
    }
    if !refresh_slot(&mut m, i) {
        return CKR_TOKEN_NOT_PRESENT;
    }

    let label = POOL_CFG.backend_label();
    let model = POOL_CFG.backend_model();
    drop(m);

    let info = unsafe { &mut *p_info };
    // CKF_RNG is the canonical PKCS#11 way to announce that this token has
    // a usable RNG (i.e. C_GenerateRandom returns real entropy). It is the
    // single most important capability bit this module sets.
    *info = CK_TOKEN_INFO {
        label: [0; 32],
        manufacturerID: [0; 32],
        model: [0; 16],
        serialNumber: [0; 16],
        flags: CKF_RNG | CKF_TOKEN_INITIALIZED | CKF_WRITE_PROTECTED,
        ulMaxSessionCount: MAX_SESSIONS as CK_ULONG,
        ulSessionCount: CK_UNAVAILABLE_INFORMATION,
        ulMaxRwSessionCount: 0,
        ulRwSessionCount: CK_UNAVAILABLE_INFORMATION,
        ulMaxPinLen: 0,
        ulMinPinLen: 0,
        ulTotalPublicMemory: CK_UNAVAILABLE_INFORMATION,
        ulFreePublicMemory: CK_UNAVAILABLE_INFORMATION,
        ulTotalPrivateMemory: CK_UNAVAILABLE_INFORMATION,
        ulFreePrivateMemory: CK_UNAVAILABLE_INFORMATION,
        hardwareVersion: CK_VERSION { major: 0, minor: 1 },
        firmwareVersion: CK_VERSION { major: 0, minor: 1 },
        utcTime: [0; 16],
    };
    pad_field(&mut info.label, label.as_bytes());
    pad_field(&mut info.manufacturerID, LIB_MFR);
    pad_field(&mut info.model, model.as_bytes());
    // serialNumber: empty (space-padded).
    info.serialNumber.fill(b' ');
    CKR_OK
}

unsafe extern "C" fn C_GetMechanismList(
    slot: CK_SLOT_ID,
    p_list: CK_MECHANISM_TYPE_PTR,
    p_count: CK_ULONG_PTR,
) -> CK_RV {
    if p_count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let m = lock();
    if !m.initialized {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (slot as usize) >= m.slots.len() {
        return CKR_SLOT_ID_INVALID;
    }
    drop(m);
    // No keyed mechanisms; the RNG capability is advertised via CKF_RNG in
    // the token info, not as a mechanism.
    let _ = p_list;
    unsafe { *p_count = 0 };
    CKR_OK
}

unsafe extern "C" fn C_GetMechanismInfo(
    _slot: CK_SLOT_ID,
    _mech: CK_MECHANISM_TYPE,
    _p_info: CK_MECHANISM_INFO_PTR,
) -> CK_RV {
    CKR_MECHANISM_INVALID
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

unsafe extern "C" fn C_OpenSession(
    slot: CK_SLOT_ID,
    flags: CK_FLAGS,
    _app: CK_VOID_PTR,
    _notify: CK_NOTIFY,
    ph_session: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    if ph_session.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if (flags & CKF_SERIAL_SESSION) == 0 {
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    }

    let mut m = lock();
    if !m.initialized {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (slot as usize) >= m.slots.len() {
        return CKR_SLOT_ID_INVALID;
    }

    let free_idx = match m.sessions.iter().position(|s| s.is_none()) {
        Some(i) => i,
        None => return CKR_HOST_MEMORY,
    };

    let pool = match Pool::open(POOL_CFG) {
        Ok(p) => p,
        Err(pool::Error::NotEnoughSources) => {
            m.slots[slot as usize].token_present = false;
            return CKR_TOKEN_NOT_PRESENT;
        }
        Err(_) => return CKR_DEVICE_ERROR,
    };
    m.slots[slot as usize].token_present = true;
    m.sessions[free_idx] = Some(Session {
        slot,
        flags,
        pool,
    });
    unsafe { *ph_session = (free_idx + 1) as CK_SESSION_HANDLE };
    CKR_OK
}

unsafe extern "C" fn C_CloseSession(h: CK_SESSION_HANDLE) -> CK_RV {
    let mut m = lock();
    if !m.initialized {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    let idx = match find_session(&m, h) {
        Some(i) => i,
        None => return CKR_SESSION_HANDLE_INVALID,
    };
    m.sessions[idx] = None;
    CKR_OK
}

unsafe extern "C" fn C_CloseAllSessions(slot: CK_SLOT_ID) -> CK_RV {
    let mut m = lock();
    if !m.initialized {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (slot as usize) >= m.slots.len() {
        return CKR_SLOT_ID_INVALID;
    }
    for s in m.sessions.iter_mut() {
        if s.as_ref().is_some_and(|x| x.slot == slot) {
            *s = None;
        }
    }
    CKR_OK
}

unsafe extern "C" fn C_GetSessionInfo(
    h: CK_SESSION_HANDLE,
    p_info: CK_SESSION_INFO_PTR,
) -> CK_RV {
    if p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let m = lock();
    if !m.initialized {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    let idx = match find_session(&m, h) {
        Some(i) => i,
        None => return CKR_SESSION_HANDLE_INVALID,
    };
    let s = m.sessions[idx].as_ref().unwrap();
    let state = if (s.flags & CKF_RW_SESSION) != 0 {
        CKS_RW_PUBLIC_SESSION
    } else {
        CKS_RO_PUBLIC_SESSION
    };
    let info = unsafe { &mut *p_info };
    *info = CK_SESSION_INFO {
        slotID: s.slot,
        state,
        flags: s.flags,
        ulDeviceError: 0,
    };
    CKR_OK
}

// ---------------------------------------------------------------------------
// The actual point of this library
// ---------------------------------------------------------------------------

unsafe extern "C" fn C_GenerateRandom(
    h: CK_SESSION_HANDLE,
    buf: CK_BYTE_PTR,
    len: CK_ULONG,
) -> CK_RV {
    if buf.is_null() && len > 0 {
        return CKR_ARGUMENTS_BAD;
    }
    let mut m = lock();
    if !m.initialized {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    let idx = match find_session(&m, h) {
        Some(i) => i,
        None => return CKR_SESSION_HANDLE_INVALID,
    };
    let s = m.sessions[idx].as_mut().unwrap();
    let slice = unsafe { std::slice::from_raw_parts_mut(buf, len as usize) };
    match s.pool.read(slice) {
        Ok(()) => CKR_OK,
        Err(_) => CKR_DEVICE_ERROR,
    }
}

unsafe extern "C" fn C_SeedRandom(
    h: CK_SESSION_HANDLE,
    _seed: CK_BYTE_PTR,
    _len: CK_ULONG,
) -> CK_RV {
    let m = lock();
    if !m.initialized || find_session(&m, h).is_none() {
        return CKR_SESSION_HANDLE_INVALID;
    }
    CKR_RANDOM_SEED_NOT_SUPPORTED
}

unsafe extern "C" fn C_WaitForSlotEvent(
    _flags: CK_FLAGS,
    _p_slot: CK_SLOT_ID_PTR,
    _reserved: CK_VOID_PTR,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

// ---------------------------------------------------------------------------
// Stubs for everything else
// ---------------------------------------------------------------------------
//
// Each of these returns CKR_FUNCTION_NOT_SUPPORTED. Their signatures must
// match the field types of CK_FUNCTION_LIST exactly. Macros cut the boilerplate.

macro_rules! stub {
    ($name:ident ($($arg:ident : $ty:ty),* $(,)?)) => {
        unsafe extern "C" fn $name($($arg: $ty),*) -> CK_RV {
            $(let _ = $arg;)*
            CKR_FUNCTION_NOT_SUPPORTED
        }
    };
}

stub!(C_InitToken(_s: CK_SLOT_ID, _p: CK_UTF8CHAR_PTR, _l: CK_ULONG, _lbl: CK_UTF8CHAR_PTR));
stub!(C_InitPIN(_h: CK_SESSION_HANDLE, _p: CK_UTF8CHAR_PTR, _l: CK_ULONG));
stub!(C_SetPIN(
    _h: CK_SESSION_HANDLE, _o: CK_UTF8CHAR_PTR, _ol: CK_ULONG,
    _n: CK_UTF8CHAR_PTR, _nl: CK_ULONG
));
stub!(C_GetOperationState(_h: CK_SESSION_HANDLE, _b: CK_BYTE_PTR, _l: CK_ULONG_PTR));
stub!(C_SetOperationState(
    _h: CK_SESSION_HANDLE, _b: CK_BYTE_PTR, _l: CK_ULONG,
    _e: CK_OBJECT_HANDLE, _a: CK_OBJECT_HANDLE
));
stub!(C_Login(_h: CK_SESSION_HANDLE, _t: CK_USER_TYPE, _p: CK_UTF8CHAR_PTR, _l: CK_ULONG));
stub!(C_Logout(_h: CK_SESSION_HANDLE));
stub!(C_CreateObject(
    _h: CK_SESSION_HANDLE, _t: CK_ATTRIBUTE_PTR, _c: CK_ULONG, _o: CK_OBJECT_HANDLE_PTR
));
stub!(C_CopyObject(
    _h: CK_SESSION_HANDLE, _o: CK_OBJECT_HANDLE, _t: CK_ATTRIBUTE_PTR,
    _c: CK_ULONG, _n: CK_OBJECT_HANDLE_PTR
));
stub!(C_DestroyObject(_h: CK_SESSION_HANDLE, _o: CK_OBJECT_HANDLE));
stub!(C_GetObjectSize(_h: CK_SESSION_HANDLE, _o: CK_OBJECT_HANDLE, _s: CK_ULONG_PTR));
stub!(C_GetAttributeValue(
    _h: CK_SESSION_HANDLE, _o: CK_OBJECT_HANDLE, _t: CK_ATTRIBUTE_PTR, _c: CK_ULONG
));
stub!(C_SetAttributeValue(
    _h: CK_SESSION_HANDLE, _o: CK_OBJECT_HANDLE, _t: CK_ATTRIBUTE_PTR, _c: CK_ULONG
));
stub!(C_FindObjectsInit(_h: CK_SESSION_HANDLE, _t: CK_ATTRIBUTE_PTR, _c: CK_ULONG));
stub!(C_FindObjects(
    _h: CK_SESSION_HANDLE, _o: CK_OBJECT_HANDLE_PTR, _m: CK_ULONG, _c: CK_ULONG_PTR
));
stub!(C_FindObjectsFinal(_h: CK_SESSION_HANDLE));

stub!(C_EncryptInit(_h: CK_SESSION_HANDLE, _m: CK_MECHANISM_PTR, _o: CK_OBJECT_HANDLE));
stub!(C_Encrypt(
    _h: CK_SESSION_HANDLE, _i: CK_BYTE_PTR, _il: CK_ULONG, _o: CK_BYTE_PTR, _ol: CK_ULONG_PTR
));
stub!(C_EncryptUpdate(
    _h: CK_SESSION_HANDLE, _i: CK_BYTE_PTR, _il: CK_ULONG, _o: CK_BYTE_PTR, _ol: CK_ULONG_PTR
));
stub!(C_EncryptFinal(_h: CK_SESSION_HANDLE, _o: CK_BYTE_PTR, _ol: CK_ULONG_PTR));
stub!(C_DecryptInit(_h: CK_SESSION_HANDLE, _m: CK_MECHANISM_PTR, _o: CK_OBJECT_HANDLE));
stub!(C_Decrypt(
    _h: CK_SESSION_HANDLE, _i: CK_BYTE_PTR, _il: CK_ULONG, _o: CK_BYTE_PTR, _ol: CK_ULONG_PTR
));
stub!(C_DecryptUpdate(
    _h: CK_SESSION_HANDLE, _i: CK_BYTE_PTR, _il: CK_ULONG, _o: CK_BYTE_PTR, _ol: CK_ULONG_PTR
));
stub!(C_DecryptFinal(_h: CK_SESSION_HANDLE, _o: CK_BYTE_PTR, _ol: CK_ULONG_PTR));
stub!(C_DigestInit(_h: CK_SESSION_HANDLE, _m: CK_MECHANISM_PTR));
stub!(C_Digest(
    _h: CK_SESSION_HANDLE, _i: CK_BYTE_PTR, _il: CK_ULONG, _o: CK_BYTE_PTR, _ol: CK_ULONG_PTR
));
stub!(C_DigestUpdate(_h: CK_SESSION_HANDLE, _i: CK_BYTE_PTR, _il: CK_ULONG));
stub!(C_DigestKey(_h: CK_SESSION_HANDLE, _o: CK_OBJECT_HANDLE));
stub!(C_DigestFinal(_h: CK_SESSION_HANDLE, _o: CK_BYTE_PTR, _ol: CK_ULONG_PTR));
stub!(C_SignInit(_h: CK_SESSION_HANDLE, _m: CK_MECHANISM_PTR, _o: CK_OBJECT_HANDLE));
stub!(C_Sign(
    _h: CK_SESSION_HANDLE, _i: CK_BYTE_PTR, _il: CK_ULONG, _o: CK_BYTE_PTR, _ol: CK_ULONG_PTR
));
stub!(C_SignUpdate(_h: CK_SESSION_HANDLE, _i: CK_BYTE_PTR, _il: CK_ULONG));
stub!(C_SignFinal(_h: CK_SESSION_HANDLE, _o: CK_BYTE_PTR, _ol: CK_ULONG_PTR));
stub!(C_SignRecoverInit(_h: CK_SESSION_HANDLE, _m: CK_MECHANISM_PTR, _o: CK_OBJECT_HANDLE));
stub!(C_SignRecover(
    _h: CK_SESSION_HANDLE, _i: CK_BYTE_PTR, _il: CK_ULONG, _o: CK_BYTE_PTR, _ol: CK_ULONG_PTR
));
stub!(C_VerifyInit(_h: CK_SESSION_HANDLE, _m: CK_MECHANISM_PTR, _o: CK_OBJECT_HANDLE));
stub!(C_Verify(
    _h: CK_SESSION_HANDLE, _i: CK_BYTE_PTR, _il: CK_ULONG, _o: CK_BYTE_PTR, _ol: CK_ULONG
));
stub!(C_VerifyUpdate(_h: CK_SESSION_HANDLE, _i: CK_BYTE_PTR, _il: CK_ULONG));
stub!(C_VerifyFinal(_h: CK_SESSION_HANDLE, _o: CK_BYTE_PTR, _ol: CK_ULONG));
stub!(C_VerifyRecoverInit(_h: CK_SESSION_HANDLE, _m: CK_MECHANISM_PTR, _o: CK_OBJECT_HANDLE));
stub!(C_VerifyRecover(
    _h: CK_SESSION_HANDLE, _i: CK_BYTE_PTR, _il: CK_ULONG, _o: CK_BYTE_PTR, _ol: CK_ULONG_PTR
));
stub!(C_DigestEncryptUpdate(
    _h: CK_SESSION_HANDLE, _i: CK_BYTE_PTR, _il: CK_ULONG, _o: CK_BYTE_PTR, _ol: CK_ULONG_PTR
));
stub!(C_DecryptDigestUpdate(
    _h: CK_SESSION_HANDLE, _i: CK_BYTE_PTR, _il: CK_ULONG, _o: CK_BYTE_PTR, _ol: CK_ULONG_PTR
));
stub!(C_SignEncryptUpdate(
    _h: CK_SESSION_HANDLE, _i: CK_BYTE_PTR, _il: CK_ULONG, _o: CK_BYTE_PTR, _ol: CK_ULONG_PTR
));
stub!(C_DecryptVerifyUpdate(
    _h: CK_SESSION_HANDLE, _i: CK_BYTE_PTR, _il: CK_ULONG, _o: CK_BYTE_PTR, _ol: CK_ULONG_PTR
));
stub!(C_GenerateKey(
    _h: CK_SESSION_HANDLE, _m: CK_MECHANISM_PTR, _t: CK_ATTRIBUTE_PTR,
    _c: CK_ULONG, _k: CK_OBJECT_HANDLE_PTR
));
stub!(C_GenerateKeyPair(
    _h: CK_SESSION_HANDLE, _m: CK_MECHANISM_PTR,
    _pubt: CK_ATTRIBUTE_PTR, _pubc: CK_ULONG,
    _prit: CK_ATTRIBUTE_PTR, _pric: CK_ULONG,
    _pubh: CK_OBJECT_HANDLE_PTR, _prih: CK_OBJECT_HANDLE_PTR
));
stub!(C_WrapKey(
    _h: CK_SESSION_HANDLE, _m: CK_MECHANISM_PTR,
    _wrap: CK_OBJECT_HANDLE, _key: CK_OBJECT_HANDLE,
    _o: CK_BYTE_PTR, _ol: CK_ULONG_PTR
));
stub!(C_UnwrapKey(
    _h: CK_SESSION_HANDLE, _m: CK_MECHANISM_PTR, _wrap: CK_OBJECT_HANDLE,
    _i: CK_BYTE_PTR, _il: CK_ULONG, _t: CK_ATTRIBUTE_PTR, _c: CK_ULONG,
    _k: CK_OBJECT_HANDLE_PTR
));
stub!(C_DeriveKey(
    _h: CK_SESSION_HANDLE, _m: CK_MECHANISM_PTR, _base: CK_OBJECT_HANDLE,
    _t: CK_ATTRIBUTE_PTR, _c: CK_ULONG, _k: CK_OBJECT_HANDLE_PTR
));
stub!(C_GetFunctionStatus(_h: CK_SESSION_HANDLE));
stub!(C_CancelFunction(_h: CK_SESSION_HANDLE));

// ---------------------------------------------------------------------------
// PKCS#11 3.x stubs
// ---------------------------------------------------------------------------

stub!(C_LoginUser(
    _h: CK_SESSION_HANDLE, _t: CK_USER_TYPE,
    _pin: CK_UTF8CHAR_PTR, _pl: CK_ULONG,
    _u: CK_UTF8CHAR_PTR, _ul: CK_ULONG
));
stub!(C_SessionCancel(_h: CK_SESSION_HANDLE, _f: CK_FLAGS));
stub!(C_MessageEncryptInit(
    _h: CK_SESSION_HANDLE, _m: CK_MECHANISM_PTR, _o: CK_OBJECT_HANDLE
));
stub!(C_EncryptMessage(
    _h: CK_SESSION_HANDLE, _p: CK_VOID_PTR, _pl: CK_ULONG,
    _aad: CK_BYTE_PTR, _aadl: CK_ULONG,
    _i: CK_BYTE_PTR, _il: CK_ULONG,
    _o: CK_BYTE_PTR, _ol: CK_ULONG_PTR
));
stub!(C_EncryptMessageBegin(
    _h: CK_SESSION_HANDLE, _p: CK_VOID_PTR, _pl: CK_ULONG,
    _aad: CK_BYTE_PTR, _aadl: CK_ULONG
));
stub!(C_EncryptMessageNext(
    _h: CK_SESSION_HANDLE, _p: CK_VOID_PTR, _pl: CK_ULONG,
    _i: CK_BYTE_PTR, _il: CK_ULONG,
    _o: CK_BYTE_PTR, _ol: CK_ULONG_PTR, _f: CK_FLAGS
));
stub!(C_MessageEncryptFinal(_h: CK_SESSION_HANDLE));
stub!(C_MessageDecryptInit(
    _h: CK_SESSION_HANDLE, _m: CK_MECHANISM_PTR, _o: CK_OBJECT_HANDLE
));
stub!(C_DecryptMessage(
    _h: CK_SESSION_HANDLE, _p: CK_VOID_PTR, _pl: CK_ULONG,
    _aad: CK_BYTE_PTR, _aadl: CK_ULONG,
    _i: CK_BYTE_PTR, _il: CK_ULONG,
    _o: CK_BYTE_PTR, _ol: CK_ULONG_PTR
));
stub!(C_DecryptMessageBegin(
    _h: CK_SESSION_HANDLE, _p: CK_VOID_PTR, _pl: CK_ULONG,
    _aad: CK_BYTE_PTR, _aadl: CK_ULONG
));
stub!(C_DecryptMessageNext(
    _h: CK_SESSION_HANDLE, _p: CK_VOID_PTR, _pl: CK_ULONG,
    _i: CK_BYTE_PTR, _il: CK_ULONG,
    _o: CK_BYTE_PTR, _ol: CK_ULONG_PTR, _f: CK_FLAGS
));
stub!(C_MessageDecryptFinal(_h: CK_SESSION_HANDLE));
stub!(C_MessageSignInit(
    _h: CK_SESSION_HANDLE, _m: CK_MECHANISM_PTR, _o: CK_OBJECT_HANDLE
));
stub!(C_SignMessage(
    _h: CK_SESSION_HANDLE, _p: CK_VOID_PTR, _pl: CK_ULONG,
    _i: CK_BYTE_PTR, _il: CK_ULONG, _o: CK_BYTE_PTR, _ol: CK_ULONG_PTR
));
stub!(C_SignMessageBegin(_h: CK_SESSION_HANDLE, _p: CK_VOID_PTR, _pl: CK_ULONG));
stub!(C_SignMessageNext(
    _h: CK_SESSION_HANDLE, _p: CK_VOID_PTR, _pl: CK_ULONG,
    _i: CK_BYTE_PTR, _il: CK_ULONG, _o: CK_BYTE_PTR, _ol: CK_ULONG_PTR
));
stub!(C_MessageSignFinal(_h: CK_SESSION_HANDLE));
stub!(C_MessageVerifyInit(
    _h: CK_SESSION_HANDLE, _m: CK_MECHANISM_PTR, _o: CK_OBJECT_HANDLE
));
stub!(C_VerifyMessage(
    _h: CK_SESSION_HANDLE, _p: CK_VOID_PTR, _pl: CK_ULONG,
    _i: CK_BYTE_PTR, _il: CK_ULONG, _s: CK_BYTE_PTR, _sl: CK_ULONG
));
stub!(C_VerifyMessageBegin(_h: CK_SESSION_HANDLE, _p: CK_VOID_PTR, _pl: CK_ULONG));
stub!(C_VerifyMessageNext(
    _h: CK_SESSION_HANDLE, _p: CK_VOID_PTR, _pl: CK_ULONG,
    _i: CK_BYTE_PTR, _il: CK_ULONG, _s: CK_BYTE_PTR, _sl: CK_ULONG
));
stub!(C_MessageVerifyFinal(_h: CK_SESSION_HANDLE));

// ---------------------------------------------------------------------------
// PKCS#11 3.x interface discovery
// ---------------------------------------------------------------------------
//
// `C_GetInterfaceList` and `C_GetInterface` are the v3 entry points apps use
// to find a function list that matches a specific spec version. We publish
// two interfaces, both named "PKCS 11":
//   - { major: 3, minor: 1 } → CK_FUNCTION_LIST_3_0 (FN_LIST_3)
//   - { major: 2, minor: 40 } → CK_FUNCTION_LIST     (FN_LIST)
// The 3.1 entry is the default (returned when the caller passes a NULL name).

const IFACE_NAME_PKCS11: &[u8; 8] = b"PKCS 11\0";

#[repr(transparent)]
struct Interfaces([CK_INTERFACE; 2]);
// SAFETY: each pointer in INTERFACES targets a 'static immutable item that
// callers must treat as read-only per the PKCS#11 contract.
unsafe impl Sync for Interfaces {}

static INTERFACES: Interfaces = Interfaces([
    CK_INTERFACE {
        pInterfaceName: IFACE_NAME_PKCS11.as_ptr() as *mut CK_UTF8CHAR,
        pFunctionList: &FN_LIST_3 as *const CK_FUNCTION_LIST_3_0 as *mut c_void,
        flags: 0,
    },
    CK_INTERFACE {
        pInterfaceName: IFACE_NAME_PKCS11.as_ptr() as *mut CK_UTF8CHAR,
        pFunctionList: &FN_LIST as *const CK_FUNCTION_LIST as *mut c_void,
        flags: 0,
    },
]);

fn iface_version(i: usize) -> CK_VERSION {
    match i {
        0 => FN_LIST_3.version,
        1 => FN_LIST.version,
        _ => CK_VERSION { major: 0, minor: 0 },
    }
}

/// PKCS#11 3.0+ direct entry point. Returns the list of supported interfaces.
/// Both a function-list field (in [`FN_LIST_3`]) and a direct dlsym-able
/// symbol — the spec requires the symbol form be discoverable before the
/// caller has any function list at all.
///
/// # Safety
///
/// `p_count` must be a writable pointer to a `CK_ULONG`. `p_list` is either
/// NULL (size query) or a writable buffer of at least `*p_count` `CK_INTERFACE`
/// entries.
#[no_mangle]
pub unsafe extern "C" fn C_GetInterfaceList(
    p_list: CK_INTERFACE_PTR,
    p_count: CK_ULONG_PTR,
) -> CK_RV {
    if p_count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let n = INTERFACES.0.len();
    let count = unsafe { &mut *p_count };
    if p_list.is_null() {
        *count = n as CK_ULONG;
        return CKR_OK;
    }
    if (*count as usize) < n {
        *count = n as CK_ULONG;
        return CKR_BUFFER_TOO_SMALL;
    }
    for (i, e) in INTERFACES.0.iter().enumerate() {
        unsafe { *p_list.add(i) = *e };
    }
    *count = n as CK_ULONG;
    CKR_OK
}

/// PKCS#11 3.0+ direct entry point. Resolves a named interface to a function
/// list. When `p_name` is NULL, returns the default (highest version) interface.
///
/// # Safety
///
/// `pp_iface` must be a writable pointer to a `CK_INTERFACE_PTR`. `p_name`,
/// when non-null, must point to a NUL-terminated UTF-8 string; `p_version`,
/// when non-null, must point to a readable `CK_VERSION`.
#[no_mangle]
pub unsafe extern "C" fn C_GetInterface(
    p_name: CK_UTF8CHAR_PTR,
    p_version: CK_VERSION_PTR,
    pp_iface: CK_INTERFACE_PTR_PTR,
    flags: CK_FLAGS,
) -> CK_RV {
    if pp_iface.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let want_name: Option<&[u8]> = if p_name.is_null() {
        None
    } else {
        // SAFETY: the spec requires p_name to be a valid C string when non-null.
        let cstr = unsafe { CStr::from_ptr(p_name as *const c_char) };
        Some(cstr.to_bytes())
    };
    let want_version: Option<CK_VERSION> = if p_version.is_null() {
        None
    } else {
        Some(unsafe { *p_version })
    };

    for (i, ent) in INTERFACES.0.iter().enumerate() {
        if let Some(w) = want_name {
            // The published name is NUL-terminated; compare without the NUL.
            let nm = &IFACE_NAME_PKCS11[..IFACE_NAME_PKCS11.len() - 1];
            if w != nm {
                continue;
            }
        }
        if let Some(v) = want_version {
            let iv = iface_version(i);
            if v.major != iv.major || v.minor != iv.minor {
                continue;
            }
        }
        if (ent.flags & flags) != flags {
            continue;
        }
        unsafe {
            *pp_iface = ent as *const CK_INTERFACE as *mut CK_INTERFACE;
        }
        return CKR_OK;
    }
    CKR_FUNCTION_FAILED
}

// ---------------------------------------------------------------------------
// Function list
// ---------------------------------------------------------------------------

static FN_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CK_VERSION { major: 2, minor: 40 },
    C_Initialize: Some(C_Initialize),
    C_Finalize: Some(C_Finalize),
    C_GetInfo: Some(C_GetInfo),
    C_GetFunctionList: Some(C_GetFunctionList),
    C_GetSlotList: Some(C_GetSlotList),
    C_GetSlotInfo: Some(C_GetSlotInfo),
    C_GetTokenInfo: Some(C_GetTokenInfo),
    C_GetMechanismList: Some(C_GetMechanismList),
    C_GetMechanismInfo: Some(C_GetMechanismInfo),
    C_InitToken: Some(C_InitToken),
    C_InitPIN: Some(C_InitPIN),
    C_SetPIN: Some(C_SetPIN),
    C_OpenSession: Some(C_OpenSession),
    C_CloseSession: Some(C_CloseSession),
    C_CloseAllSessions: Some(C_CloseAllSessions),
    C_GetSessionInfo: Some(C_GetSessionInfo),
    C_GetOperationState: Some(C_GetOperationState),
    C_SetOperationState: Some(C_SetOperationState),
    C_Login: Some(C_Login),
    C_Logout: Some(C_Logout),
    C_CreateObject: Some(C_CreateObject),
    C_CopyObject: Some(C_CopyObject),
    C_DestroyObject: Some(C_DestroyObject),
    C_GetObjectSize: Some(C_GetObjectSize),
    C_GetAttributeValue: Some(C_GetAttributeValue),
    C_SetAttributeValue: Some(C_SetAttributeValue),
    C_FindObjectsInit: Some(C_FindObjectsInit),
    C_FindObjects: Some(C_FindObjects),
    C_FindObjectsFinal: Some(C_FindObjectsFinal),
    C_EncryptInit: Some(C_EncryptInit),
    C_Encrypt: Some(C_Encrypt),
    C_EncryptUpdate: Some(C_EncryptUpdate),
    C_EncryptFinal: Some(C_EncryptFinal),
    C_DecryptInit: Some(C_DecryptInit),
    C_Decrypt: Some(C_Decrypt),
    C_DecryptUpdate: Some(C_DecryptUpdate),
    C_DecryptFinal: Some(C_DecryptFinal),
    C_DigestInit: Some(C_DigestInit),
    C_Digest: Some(C_Digest),
    C_DigestUpdate: Some(C_DigestUpdate),
    C_DigestKey: Some(C_DigestKey),
    C_DigestFinal: Some(C_DigestFinal),
    C_SignInit: Some(C_SignInit),
    C_Sign: Some(C_Sign),
    C_SignUpdate: Some(C_SignUpdate),
    C_SignFinal: Some(C_SignFinal),
    C_SignRecoverInit: Some(C_SignRecoverInit),
    C_SignRecover: Some(C_SignRecover),
    C_VerifyInit: Some(C_VerifyInit),
    C_Verify: Some(C_Verify),
    C_VerifyUpdate: Some(C_VerifyUpdate),
    C_VerifyFinal: Some(C_VerifyFinal),
    C_VerifyRecoverInit: Some(C_VerifyRecoverInit),
    C_VerifyRecover: Some(C_VerifyRecover),
    C_DigestEncryptUpdate: Some(C_DigestEncryptUpdate),
    C_DecryptDigestUpdate: Some(C_DecryptDigestUpdate),
    C_SignEncryptUpdate: Some(C_SignEncryptUpdate),
    C_DecryptVerifyUpdate: Some(C_DecryptVerifyUpdate),
    C_GenerateKey: Some(C_GenerateKey),
    C_GenerateKeyPair: Some(C_GenerateKeyPair),
    C_WrapKey: Some(C_WrapKey),
    C_UnwrapKey: Some(C_UnwrapKey),
    C_DeriveKey: Some(C_DeriveKey),
    C_SeedRandom: Some(C_SeedRandom),
    C_GenerateRandom: Some(C_GenerateRandom),
    C_GetFunctionStatus: Some(C_GetFunctionStatus),
    C_CancelFunction: Some(C_CancelFunction),
    C_WaitForSlotEvent: Some(C_WaitForSlotEvent),
};

// PKCS#11 3.x function list. Backs the "PKCS 11" v3.1 interface. The struct
// shape is the 3.0 ABI; 3.1 added clarifications but no new functions, so the
// version field carries 3.1 while every entry past `C_WaitForSlotEvent` that
// we don't actually implement points at a `CKR_FUNCTION_NOT_SUPPORTED` stub.
static FN_LIST_3: CK_FUNCTION_LIST_3_0 = CK_FUNCTION_LIST_3_0 {
    version: CK_VERSION { major: 3, minor: 1 },
    C_Initialize: Some(C_Initialize),
    C_Finalize: Some(C_Finalize),
    C_GetInfo: Some(C_GetInfo),
    C_GetFunctionList: Some(C_GetFunctionList),
    C_GetSlotList: Some(C_GetSlotList),
    C_GetSlotInfo: Some(C_GetSlotInfo),
    C_GetTokenInfo: Some(C_GetTokenInfo),
    C_GetMechanismList: Some(C_GetMechanismList),
    C_GetMechanismInfo: Some(C_GetMechanismInfo),
    C_InitToken: Some(C_InitToken),
    C_InitPIN: Some(C_InitPIN),
    C_SetPIN: Some(C_SetPIN),
    C_OpenSession: Some(C_OpenSession),
    C_CloseSession: Some(C_CloseSession),
    C_CloseAllSessions: Some(C_CloseAllSessions),
    C_GetSessionInfo: Some(C_GetSessionInfo),
    C_GetOperationState: Some(C_GetOperationState),
    C_SetOperationState: Some(C_SetOperationState),
    C_Login: Some(C_Login),
    C_Logout: Some(C_Logout),
    C_CreateObject: Some(C_CreateObject),
    C_CopyObject: Some(C_CopyObject),
    C_DestroyObject: Some(C_DestroyObject),
    C_GetObjectSize: Some(C_GetObjectSize),
    C_GetAttributeValue: Some(C_GetAttributeValue),
    C_SetAttributeValue: Some(C_SetAttributeValue),
    C_FindObjectsInit: Some(C_FindObjectsInit),
    C_FindObjects: Some(C_FindObjects),
    C_FindObjectsFinal: Some(C_FindObjectsFinal),
    C_EncryptInit: Some(C_EncryptInit),
    C_Encrypt: Some(C_Encrypt),
    C_EncryptUpdate: Some(C_EncryptUpdate),
    C_EncryptFinal: Some(C_EncryptFinal),
    C_DecryptInit: Some(C_DecryptInit),
    C_Decrypt: Some(C_Decrypt),
    C_DecryptUpdate: Some(C_DecryptUpdate),
    C_DecryptFinal: Some(C_DecryptFinal),
    C_DigestInit: Some(C_DigestInit),
    C_Digest: Some(C_Digest),
    C_DigestUpdate: Some(C_DigestUpdate),
    C_DigestKey: Some(C_DigestKey),
    C_DigestFinal: Some(C_DigestFinal),
    C_SignInit: Some(C_SignInit),
    C_Sign: Some(C_Sign),
    C_SignUpdate: Some(C_SignUpdate),
    C_SignFinal: Some(C_SignFinal),
    C_SignRecoverInit: Some(C_SignRecoverInit),
    C_SignRecover: Some(C_SignRecover),
    C_VerifyInit: Some(C_VerifyInit),
    C_Verify: Some(C_Verify),
    C_VerifyUpdate: Some(C_VerifyUpdate),
    C_VerifyFinal: Some(C_VerifyFinal),
    C_VerifyRecoverInit: Some(C_VerifyRecoverInit),
    C_VerifyRecover: Some(C_VerifyRecover),
    C_DigestEncryptUpdate: Some(C_DigestEncryptUpdate),
    C_DecryptDigestUpdate: Some(C_DecryptDigestUpdate),
    C_SignEncryptUpdate: Some(C_SignEncryptUpdate),
    C_DecryptVerifyUpdate: Some(C_DecryptVerifyUpdate),
    C_GenerateKey: Some(C_GenerateKey),
    C_GenerateKeyPair: Some(C_GenerateKeyPair),
    C_WrapKey: Some(C_WrapKey),
    C_UnwrapKey: Some(C_UnwrapKey),
    C_DeriveKey: Some(C_DeriveKey),
    C_SeedRandom: Some(C_SeedRandom),
    C_GenerateRandom: Some(C_GenerateRandom),
    C_GetFunctionStatus: Some(C_GetFunctionStatus),
    C_CancelFunction: Some(C_CancelFunction),
    C_WaitForSlotEvent: Some(C_WaitForSlotEvent),
    C_GetInterfaceList: Some(C_GetInterfaceList),
    C_GetInterface: Some(C_GetInterface),
    C_LoginUser: Some(C_LoginUser),
    C_SessionCancel: Some(C_SessionCancel),
    C_MessageEncryptInit: Some(C_MessageEncryptInit),
    C_EncryptMessage: Some(C_EncryptMessage),
    C_EncryptMessageBegin: Some(C_EncryptMessageBegin),
    C_EncryptMessageNext: Some(C_EncryptMessageNext),
    C_MessageEncryptFinal: Some(C_MessageEncryptFinal),
    C_MessageDecryptInit: Some(C_MessageDecryptInit),
    C_DecryptMessage: Some(C_DecryptMessage),
    C_DecryptMessageBegin: Some(C_DecryptMessageBegin),
    C_DecryptMessageNext: Some(C_DecryptMessageNext),
    C_MessageDecryptFinal: Some(C_MessageDecryptFinal),
    C_MessageSignInit: Some(C_MessageSignInit),
    C_SignMessage: Some(C_SignMessage),
    C_SignMessageBegin: Some(C_SignMessageBegin),
    C_SignMessageNext: Some(C_SignMessageNext),
    C_MessageSignFinal: Some(C_MessageSignFinal),
    C_MessageVerifyInit: Some(C_MessageVerifyInit),
    C_VerifyMessage: Some(C_VerifyMessage),
    C_VerifyMessageBegin: Some(C_VerifyMessageBegin),
    C_VerifyMessageNext: Some(C_VerifyMessageNext),
    C_MessageVerifyFinal: Some(C_MessageVerifyFinal),
};

/// The one symbol every PKCS#11 consumer resolves via dlsym. Safe to call
/// before `C_Initialize`.
///
/// # Safety
///
/// `pp_list` must be either NULL or a writable pointer to a
/// `CK_FUNCTION_LIST_PTR`. On success, `*pp_list` is set to a process-wide
/// static table whose lifetime equals the loaded module's lifetime; the
/// caller must not outlive the module.
#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(pp_list: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    if pp_list.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        *pp_list = &FN_LIST as *const CK_FUNCTION_LIST as *mut CK_FUNCTION_LIST;
    }
    CKR_OK
}


