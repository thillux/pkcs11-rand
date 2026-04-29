/* PKCS#11 v2.40 RNG-only provider.
 *
 * One slot per PC/SC reader is published at C_Initialize time. C_GenerateRandom
 * is the only crypto entrypoint backed by real device work; everything else
 * is either trivial bookkeeping or returns CKR_FUNCTION_NOT_SUPPORTED.
 *
 * Threading: the spec requires us to be safe against concurrent calls from
 * application threads as long as the app passed CKF_OS_LOCKING_OK or
 * NULL args. We take a single global mutex around all state mutations,
 * including the per-card APDU exchange — which serializes the underlying
 * card anyway, so there is no value in finer-grained locking.
 */

#define _POSIX_C_SOURCE 200809L

#include "../include/pkcs11.h"
#include "rng.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LIB_DESC      "mini-pkcs11-rand RNG provider"
#define LIB_MFR       "mini-pkcs11-rand"
#define MAX_SESSIONS  64

/* Pad a fixed-width field with spaces (PKCS#11 strings are space-padded,
 * NOT null-terminated). */
static void pad_str(CK_UTF8CHAR *dst, size_t cap, const char *src)
{
    size_t n = strlen(src);
    if (n > cap) n = cap;
    memcpy(dst, src, n);
    if (n < cap) memset(dst + n, ' ', cap - n);
}

/* Padded copy into the CK_CHAR (ASCII) fields. Same rule. */
static void pad_chr(CK_CHAR *dst, size_t cap, const char *src)
{
    pad_str((CK_UTF8CHAR *)dst, cap, src);
}

/* --- module state ------------------------------------------------------- */

typedef struct {
    char *reader;        /* owned device/reader name */
    int   token_present; /* last probed: 1 = usable, 0 = empty/unsupported */
} slot_t;

typedef struct {
    int        in_use;
    CK_SLOT_ID slot;
    CK_FLAGS   flags;
    rng_dev   *card;     /* opaque per-session backend handle */
} session_t;

static pthread_mutex_t g_lock        = PTHREAD_MUTEX_INITIALIZER;
static int             g_initialized;
static slot_t         *g_slots;
static size_t          g_nslots;
static session_t       g_sessions[MAX_SESSIONS];
static CK_SESSION_HANDLE g_next_handle = 1;

static void free_slots(void)
{
    for (size_t i = 0; i < g_nslots; i++) free(g_slots[i].reader);
    free(g_slots);
    g_slots  = NULL;
    g_nslots = 0;
}

/* Probe one slot and update its cached presence. Caller holds g_lock.
 * Returns the up-to-date `token_present` flag. */
static int refresh_slot(size_t i)
{
    g_slots[i].token_present = (rng_probe(g_slots[i].reader) == 1);
    return g_slots[i].token_present;
}

/* --- entrypoints (declared CK_RV; this module has C calling convention
 *     on all supported Unix platforms, which matches Cryptoki on Unix) ---*/

CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
    pthread_mutex_lock(&g_lock);
    if (g_initialized) {
        pthread_mutex_unlock(&g_lock);
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }

    if (pInitArgs) {
        CK_C_INITIALIZE_ARGS *a = (CK_C_INITIALIZE_ARGS *)pInitArgs;
        if (a->pReserved) {
            pthread_mutex_unlock(&g_lock);
            return CKR_ARGUMENTS_BAD;
        }
        /* We are thread-safe with our own pthread mutex, so OS_LOCKING_OK
         * is fine and app-supplied locking primitives are accepted but
         * ignored (the spec allows this). If the app forbade *any*
         * threads of its own we still don't create any, so that's fine. */
        (void)a;
    }

    if (rng_global_init() < 0) {
        pthread_mutex_unlock(&g_lock);
        return CKR_FUNCTION_FAILED;
    }

    char  **names = NULL;
    size_t  count = 0;
    if (rng_list(&names, &count) < 0) {
        rng_global_shutdown();
        pthread_mutex_unlock(&g_lock);
        return CKR_FUNCTION_FAILED;
    }

    if (count) {
        g_slots = calloc(count, sizeof(*g_slots));
        if (!g_slots) {
            rng_free_names(names, count);
            rng_global_shutdown();
            pthread_mutex_unlock(&g_lock);
            return CKR_HOST_MEMORY;
        }
        for (size_t i = 0; i < count; i++) {
            g_slots[i].reader = strdup(names[i]);
            if (!g_slots[i].reader) {
                rng_free_names(names, count);
                free_slots();
                rng_global_shutdown();
                pthread_mutex_unlock(&g_lock);
                return CKR_HOST_MEMORY;
            }
        }
        g_nslots = count;
    }
    rng_free_names(names, count);

    memset(g_sessions, 0, sizeof(g_sessions));
    g_next_handle = 1;
    g_initialized = 1;
    pthread_mutex_unlock(&g_lock);
    return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
    if (pReserved) return CKR_ARGUMENTS_BAD;

    pthread_mutex_lock(&g_lock);
    if (!g_initialized) {
        pthread_mutex_unlock(&g_lock);
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    for (size_t i = 0; i < MAX_SESSIONS; i++) {
        if (g_sessions[i].in_use) {
            rng_close(g_sessions[i].card);
            g_sessions[i].in_use = 0;
            g_sessions[i].card   = NULL;
        }
    }
    free_slots();
    rng_global_shutdown();
    g_initialized = 0;
    pthread_mutex_unlock(&g_lock);
    return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
    if (!pInfo) return CKR_ARGUMENTS_BAD;
    pthread_mutex_lock(&g_lock);
    if (!g_initialized) { pthread_mutex_unlock(&g_lock); return CKR_CRYPTOKI_NOT_INITIALIZED; }
    pthread_mutex_unlock(&g_lock);

    memset(pInfo, 0, sizeof(*pInfo));
    pInfo->cryptokiVersion.major = 2;
    pInfo->cryptokiVersion.minor = 40;
    pad_str(pInfo->manufacturerID,     sizeof(pInfo->manufacturerID),     LIB_MFR);
    pad_str(pInfo->libraryDescription, sizeof(pInfo->libraryDescription), LIB_DESC);
    pInfo->libraryVersion.major = 0;
    pInfo->libraryVersion.minor = 1;
    return CKR_OK;
}

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pList,
                           CK_ULONG_PTR pCount)
{
    if (!pCount) return CKR_ARGUMENTS_BAD;
    pthread_mutex_lock(&g_lock);
    if (!g_initialized) { pthread_mutex_unlock(&g_lock); return CKR_CRYPTOKI_NOT_INITIALIZED; }

    /* When the caller filters on tokenPresent, probe each reader so the
     * answer reflects the live state of the world. Without the filter we
     * just enumerate all reader slots — the slot ID stays the reader
     * index regardless, so consumers see stable IDs across calls. */
    size_t want = 0;
    for (size_t i = 0; i < g_nslots; i++) {
        if (tokenPresent) {
            if (!refresh_slot(i)) continue;
        }
        want++;
    }

    if (!pList) {
        *pCount = want;
        pthread_mutex_unlock(&g_lock);
        return CKR_OK;
    }
    if (*pCount < want) {
        *pCount = want;
        pthread_mutex_unlock(&g_lock);
        return CKR_BUFFER_TOO_SMALL;
    }

    size_t out = 0;
    for (size_t i = 0; i < g_nslots; i++) {
        if (tokenPresent && !g_slots[i].token_present) continue;
        pList[out++] = (CK_SLOT_ID)i;
    }
    *pCount = out;
    pthread_mutex_unlock(&g_lock);
    return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slot, CK_SLOT_INFO_PTR pInfo)
{
    if (!pInfo) return CKR_ARGUMENTS_BAD;
    pthread_mutex_lock(&g_lock);
    if (!g_initialized) { pthread_mutex_unlock(&g_lock); return CKR_CRYPTOKI_NOT_INITIALIZED; }
    if (slot >= g_nslots) { pthread_mutex_unlock(&g_lock); return CKR_SLOT_ID_INVALID; }

    memset(pInfo, 0, sizeof(*pInfo));
    pad_str(pInfo->slotDescription, sizeof(pInfo->slotDescription), g_slots[slot].reader);
    pad_str(pInfo->manufacturerID,  sizeof(pInfo->manufacturerID),  LIB_MFR);
    int present = refresh_slot(slot);
    pInfo->flags = CKF_HW_SLOT | CKF_REMOVABLE_DEVICE | (present ? CKF_TOKEN_PRESENT : 0);
    pthread_mutex_unlock(&g_lock);
    return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slot, CK_TOKEN_INFO_PTR pInfo)
{
    if (!pInfo) return CKR_ARGUMENTS_BAD;
    pthread_mutex_lock(&g_lock);
    if (!g_initialized) { pthread_mutex_unlock(&g_lock); return CKR_CRYPTOKI_NOT_INITIALIZED; }
    if (slot >= g_nslots) { pthread_mutex_unlock(&g_lock); return CKR_SLOT_ID_INVALID; }
    if (!refresh_slot(slot)) { pthread_mutex_unlock(&g_lock); return CKR_TOKEN_NOT_PRESENT; }

    /* We label generically; the reader name in slotDescription is what
     * uniquely identifies the device. */
    memset(pInfo, 0, sizeof(*pInfo));
    pad_str(pInfo->label,          sizeof(pInfo->label),          rng_backend_label());
    pad_str(pInfo->manufacturerID, sizeof(pInfo->manufacturerID), LIB_MFR);
    pad_str(pInfo->model,          sizeof(pInfo->model),          rng_backend_model());
    pad_chr(pInfo->serialNumber,   sizeof(pInfo->serialNumber),   "");
    pInfo->flags = CKF_RNG | CKF_TOKEN_INITIALIZED | CKF_WRITE_PROTECTED;
    pInfo->ulMaxSessionCount   = MAX_SESSIONS;
    pInfo->ulSessionCount      = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulMaxRwSessionCount = 0;
    pInfo->ulRwSessionCount    = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulMaxPinLen         = 0;
    pInfo->ulMinPinLen         = 0;
    pInfo->ulTotalPublicMemory  = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePublicMemory   = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePrivateMemory  = CK_UNAVAILABLE_INFORMATION;
    pthread_mutex_unlock(&g_lock);
    return CKR_OK;
}

CK_RV C_GetMechanismList(CK_SLOT_ID slot, CK_MECHANISM_TYPE_PTR pList,
                                CK_ULONG_PTR pCount)
{
    if (!pCount) return CKR_ARGUMENTS_BAD;
    pthread_mutex_lock(&g_lock);
    if (!g_initialized) { pthread_mutex_unlock(&g_lock); return CKR_CRYPTOKI_NOT_INITIALIZED; }
    if (slot >= g_nslots) { pthread_mutex_unlock(&g_lock); return CKR_SLOT_ID_INVALID; }
    pthread_mutex_unlock(&g_lock);

    /* No keyed mechanisms; the RNG capability is advertised via
     * CKF_RNG in the token info, not as a mechanism. */
    if (!pList) { *pCount = 0; return CKR_OK; }
    *pCount = 0;
    return CKR_OK;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slot, CK_MECHANISM_TYPE m,
                                CK_MECHANISM_INFO_PTR pInfo)
{
    (void)slot; (void)m; (void)pInfo;
    return CKR_MECHANISM_INVALID;
}

/* --- sessions ----------------------------------------------------------- */

static int find_session(CK_SESSION_HANDLE h, size_t *idx_out)
{
    for (size_t i = 0; i < MAX_SESSIONS; i++) {
        if (g_sessions[i].in_use && (CK_SESSION_HANDLE)(i + 1) == h) {
            if (idx_out) *idx_out = i;
            return 1;
        }
    }
    return 0;
}

CK_RV C_OpenSession(CK_SLOT_ID slot, CK_FLAGS flags,
                           CK_VOID_PTR app, CK_NOTIFY notify,
                           CK_SESSION_HANDLE_PTR phSession)
{
    (void)app; (void)notify;
    if (!phSession) return CKR_ARGUMENTS_BAD;
    if (!(flags & CKF_SERIAL_SESSION)) return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

    pthread_mutex_lock(&g_lock);
    if (!g_initialized) { pthread_mutex_unlock(&g_lock); return CKR_CRYPTOKI_NOT_INITIALIZED; }
    if (slot >= g_nslots) { pthread_mutex_unlock(&g_lock); return CKR_SLOT_ID_INVALID; }

    size_t free_idx = MAX_SESSIONS;
    for (size_t i = 0; i < MAX_SESSIONS; i++) {
        if (!g_sessions[i].in_use) { free_idx = i; break; }
    }
    if (free_idx == MAX_SESSIONS) {
        pthread_mutex_unlock(&g_lock);
        return CKR_HOST_MEMORY;
    }

    rng_dev *card = NULL;
    int crv = rng_open(g_slots[slot].reader, &card);
    if (crv != 0) {
        g_slots[slot].token_present = 0;
        pthread_mutex_unlock(&g_lock);
        return crv == -2 ? CKR_TOKEN_NOT_PRESENT : CKR_DEVICE_ERROR;
    }
    g_slots[slot].token_present = 1;

    g_sessions[free_idx].in_use = 1;
    g_sessions[free_idx].slot   = slot;
    g_sessions[free_idx].flags  = flags;
    g_sessions[free_idx].card   = card;
    *phSession = (CK_SESSION_HANDLE)(free_idx + 1);
    /* Advance g_next_handle just for visibility/debugging; we still bind
     * handles to slot index above. */
    g_next_handle++;
    pthread_mutex_unlock(&g_lock);
    return CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE h)
{
    pthread_mutex_lock(&g_lock);
    if (!g_initialized) { pthread_mutex_unlock(&g_lock); return CKR_CRYPTOKI_NOT_INITIALIZED; }
    size_t idx;
    if (!find_session(h, &idx)) {
        pthread_mutex_unlock(&g_lock);
        return CKR_SESSION_HANDLE_INVALID;
    }
    rng_close(g_sessions[idx].card);
    g_sessions[idx].in_use = 0;
    g_sessions[idx].card   = NULL;
    pthread_mutex_unlock(&g_lock);
    return CKR_OK;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slot)
{
    pthread_mutex_lock(&g_lock);
    if (!g_initialized) { pthread_mutex_unlock(&g_lock); return CKR_CRYPTOKI_NOT_INITIALIZED; }
    if (slot >= g_nslots) { pthread_mutex_unlock(&g_lock); return CKR_SLOT_ID_INVALID; }
    for (size_t i = 0; i < MAX_SESSIONS; i++) {
        if (g_sessions[i].in_use && g_sessions[i].slot == slot) {
            rng_close(g_sessions[i].card);
            g_sessions[i].in_use = 0;
            g_sessions[i].card   = NULL;
        }
    }
    pthread_mutex_unlock(&g_lock);
    return CKR_OK;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE h, CK_SESSION_INFO_PTR pInfo)
{
    if (!pInfo) return CKR_ARGUMENTS_BAD;
    pthread_mutex_lock(&g_lock);
    if (!g_initialized) { pthread_mutex_unlock(&g_lock); return CKR_CRYPTOKI_NOT_INITIALIZED; }
    size_t idx;
    if (!find_session(h, &idx)) { pthread_mutex_unlock(&g_lock); return CKR_SESSION_HANDLE_INVALID; }

    memset(pInfo, 0, sizeof(*pInfo));
    pInfo->slotID        = g_sessions[idx].slot;
    pInfo->state         = (g_sessions[idx].flags & CKF_RW_SESSION)
                               ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
    pInfo->flags         = g_sessions[idx].flags;
    pInfo->ulDeviceError = 0;
    pthread_mutex_unlock(&g_lock);
    return CKR_OK;
}

/* --- the actual point of this library --------------------------------- */

CK_RV C_GenerateRandom(CK_SESSION_HANDLE h, CK_BYTE_PTR buf, CK_ULONG len)
{
    if (!buf && len) return CKR_ARGUMENTS_BAD;
    pthread_mutex_lock(&g_lock);
    if (!g_initialized) { pthread_mutex_unlock(&g_lock); return CKR_CRYPTOKI_NOT_INITIALIZED; }
    size_t idx;
    if (!find_session(h, &idx)) { pthread_mutex_unlock(&g_lock); return CKR_SESSION_HANDLE_INVALID; }
    rng_dev *card = g_sessions[idx].card;

    int rv = rng_read(card, buf, (size_t)len);
    pthread_mutex_unlock(&g_lock);
    return rv == 0 ? CKR_OK : CKR_DEVICE_ERROR;
}

CK_RV C_SeedRandom(CK_SESSION_HANDLE h, CK_BYTE_PTR seed, CK_ULONG len)
{
    (void)seed; (void)len;
    pthread_mutex_lock(&g_lock);
    int ok = g_initialized && find_session(h, NULL);
    pthread_mutex_unlock(&g_lock);
    if (!ok) return CKR_SESSION_HANDLE_INVALID;
    return CKR_RANDOM_SEED_NOT_SUPPORTED;
}

CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot,
                                CK_VOID_PTR reserved)
{
    (void)flags; (void)pSlot; (void)reserved;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* --- not-supported stubs ---------------------------------------------- */

/* The stub bodies are non-static so their signatures match the prototypes
 * declared by pkcs11.h. With -fvisibility=hidden they are not exported. */
#define STUB1(name, t1)            CK_RV name(t1 a) { (void)a; return CKR_FUNCTION_NOT_SUPPORTED; }
#define STUB2(name, t1, t2)        CK_RV name(t1 a, t2 b) { (void)a; (void)b; return CKR_FUNCTION_NOT_SUPPORTED; }
#define STUB3(name, t1, t2, t3)    CK_RV name(t1 a, t2 b, t3 c) { (void)a; (void)b; (void)c; return CKR_FUNCTION_NOT_SUPPORTED; }
#define STUB4(name, t1, t2, t3, t4) CK_RV name(t1 a, t2 b, t3 c, t4 d) { (void)a; (void)b; (void)c; (void)d; return CKR_FUNCTION_NOT_SUPPORTED; }
#define STUB5(name, t1, t2, t3, t4, t5) CK_RV name(t1 a, t2 b, t3 c, t4 d, t5 e) { (void)a; (void)b; (void)c; (void)d; (void)e; return CKR_FUNCTION_NOT_SUPPORTED; }
#define STUB6(name, t1, t2, t3, t4, t5, t6) CK_RV name(t1 a, t2 b, t3 c, t4 d, t5 e, t6 f) { (void)a; (void)b; (void)c; (void)d; (void)e; (void)f; return CKR_FUNCTION_NOT_SUPPORTED; }
#define STUB8(name, t1, t2, t3, t4, t5, t6, t7, t8) CK_RV name(t1 a, t2 b, t3 c, t4 d, t5 e, t6 f, t7 g, t8 h) { (void)a; (void)b; (void)c; (void)d; (void)e; (void)f; (void)g; (void)h; return CKR_FUNCTION_NOT_SUPPORTED; }

STUB4(C_InitToken,       CK_SLOT_ID, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR)
STUB3(C_InitPIN,         CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG)
STUB5(C_SetPIN,          CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR, CK_ULONG)
STUB3(C_GetOperationState, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR)
STUB5(C_SetOperationState, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)
STUB4(C_Login,           CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_ULONG)
STUB1(C_Logout,          CK_SESSION_HANDLE)
STUB4(C_CreateObject,    CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR)
STUB5(C_CopyObject,      CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR)
STUB2(C_DestroyObject,   CK_SESSION_HANDLE, CK_OBJECT_HANDLE)
STUB3(C_GetObjectSize,   CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG_PTR)
STUB4(C_GetAttributeValue, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG)
STUB4(C_SetAttributeValue, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG)
STUB3(C_FindObjectsInit, CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG)
STUB4(C_FindObjects,     CK_SESSION_HANDLE, CK_OBJECT_HANDLE_PTR, CK_ULONG, CK_ULONG_PTR)
STUB1(C_FindObjectsFinal, CK_SESSION_HANDLE)

STUB3(C_EncryptInit,     CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE)
STUB5(C_Encrypt,         CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
STUB5(C_EncryptUpdate,   CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
STUB3(C_EncryptFinal,    CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR)
STUB3(C_DecryptInit,     CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE)
STUB5(C_Decrypt,         CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
STUB5(C_DecryptUpdate,   CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
STUB3(C_DecryptFinal,    CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR)
STUB2(C_DigestInit,      CK_SESSION_HANDLE, CK_MECHANISM_PTR)
STUB5(C_Digest,          CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
STUB3(C_DigestUpdate,    CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG)
STUB2(C_DigestKey,       CK_SESSION_HANDLE, CK_OBJECT_HANDLE)
STUB3(C_DigestFinal,     CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR)
STUB3(C_SignInit,        CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE)
STUB5(C_Sign,            CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
STUB3(C_SignUpdate,      CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG)
STUB3(C_SignFinal,       CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR)
STUB3(C_SignRecoverInit, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE)
STUB5(C_SignRecover,     CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
STUB3(C_VerifyInit,      CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE)
STUB5(C_Verify,          CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG)
STUB3(C_VerifyUpdate,    CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG)
STUB3(C_VerifyFinal,     CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG)
STUB3(C_VerifyRecoverInit, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE)
STUB5(C_VerifyRecover,   CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
STUB5(C_DigestEncryptUpdate, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
STUB5(C_DecryptDigestUpdate, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
STUB5(C_SignEncryptUpdate,   CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
STUB5(C_DecryptVerifyUpdate, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
STUB5(C_GenerateKey,     CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR)
STUB8(C_GenerateKeyPair, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR, CK_OBJECT_HANDLE_PTR)
STUB6(C_WrapKey,         CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR)
STUB8(C_UnwrapKey,       CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR)
STUB6(C_DeriveKey,       CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR)
STUB1(C_GetFunctionStatus, CK_SESSION_HANDLE)
STUB1(C_CancelFunction,    CK_SESSION_HANDLE)

/* --- function list ----------------------------------------------------- */

static CK_FUNCTION_LIST g_funcs;

/* The one symbol every PKCS#11 consumer resolves via dlsym(). It is safe
 * to call before C_Initialize, so the function-list table is populated by
 * a constructor below. The prototype itself comes from pkcs11.h; here we
 * just re-declare it with default visibility before defining it, so the
 * exported-symbol table contains exactly this one entry. */
__attribute__((visibility("default")))
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppList)
{
    if (!ppList) return CKR_ARGUMENTS_BAD;
    *ppList = &g_funcs;
    return CKR_OK;
}

/* Initialize the function list at load time so C_GetFunctionList is safe to
 * call before C_Initialize (which is the whole point of C_GetFunctionList). */
static __attribute__((constructor)) void init_funcs(void)
{
    g_funcs.version.major = 2;
    g_funcs.version.minor = 40;
    g_funcs.C_Initialize             = C_Initialize;
    g_funcs.C_Finalize               = C_Finalize;
    g_funcs.C_GetInfo                = C_GetInfo;
    g_funcs.C_GetFunctionList        = C_GetFunctionList;
    g_funcs.C_GetSlotList            = C_GetSlotList;
    g_funcs.C_GetSlotInfo            = C_GetSlotInfo;
    g_funcs.C_GetTokenInfo           = C_GetTokenInfo;
    g_funcs.C_GetMechanismList       = C_GetMechanismList;
    g_funcs.C_GetMechanismInfo       = C_GetMechanismInfo;
    g_funcs.C_InitToken              = C_InitToken;
    g_funcs.C_InitPIN                = C_InitPIN;
    g_funcs.C_SetPIN                 = C_SetPIN;
    g_funcs.C_OpenSession            = C_OpenSession;
    g_funcs.C_CloseSession           = C_CloseSession;
    g_funcs.C_CloseAllSessions       = C_CloseAllSessions;
    g_funcs.C_GetSessionInfo         = C_GetSessionInfo;
    g_funcs.C_GetOperationState      = C_GetOperationState;
    g_funcs.C_SetOperationState      = C_SetOperationState;
    g_funcs.C_Login                  = C_Login;
    g_funcs.C_Logout                 = C_Logout;
    g_funcs.C_CreateObject           = C_CreateObject;
    g_funcs.C_CopyObject             = C_CopyObject;
    g_funcs.C_DestroyObject          = C_DestroyObject;
    g_funcs.C_GetObjectSize          = C_GetObjectSize;
    g_funcs.C_GetAttributeValue      = C_GetAttributeValue;
    g_funcs.C_SetAttributeValue      = C_SetAttributeValue;
    g_funcs.C_FindObjectsInit        = C_FindObjectsInit;
    g_funcs.C_FindObjects            = C_FindObjects;
    g_funcs.C_FindObjectsFinal       = C_FindObjectsFinal;
    g_funcs.C_EncryptInit            = C_EncryptInit;
    g_funcs.C_Encrypt                = C_Encrypt;
    g_funcs.C_EncryptUpdate          = C_EncryptUpdate;
    g_funcs.C_EncryptFinal           = C_EncryptFinal;
    g_funcs.C_DecryptInit            = C_DecryptInit;
    g_funcs.C_Decrypt                = C_Decrypt;
    g_funcs.C_DecryptUpdate          = C_DecryptUpdate;
    g_funcs.C_DecryptFinal           = C_DecryptFinal;
    g_funcs.C_DigestInit             = C_DigestInit;
    g_funcs.C_Digest                 = C_Digest;
    g_funcs.C_DigestUpdate           = C_DigestUpdate;
    g_funcs.C_DigestKey              = C_DigestKey;
    g_funcs.C_DigestFinal            = C_DigestFinal;
    g_funcs.C_SignInit               = C_SignInit;
    g_funcs.C_Sign                   = C_Sign;
    g_funcs.C_SignUpdate             = C_SignUpdate;
    g_funcs.C_SignFinal              = C_SignFinal;
    g_funcs.C_SignRecoverInit        = C_SignRecoverInit;
    g_funcs.C_SignRecover            = C_SignRecover;
    g_funcs.C_VerifyInit             = C_VerifyInit;
    g_funcs.C_Verify                 = C_Verify;
    g_funcs.C_VerifyUpdate           = C_VerifyUpdate;
    g_funcs.C_VerifyFinal            = C_VerifyFinal;
    g_funcs.C_VerifyRecoverInit      = C_VerifyRecoverInit;
    g_funcs.C_VerifyRecover          = C_VerifyRecover;
    g_funcs.C_DigestEncryptUpdate    = C_DigestEncryptUpdate;
    g_funcs.C_DecryptDigestUpdate    = C_DecryptDigestUpdate;
    g_funcs.C_SignEncryptUpdate      = C_SignEncryptUpdate;
    g_funcs.C_DecryptVerifyUpdate    = C_DecryptVerifyUpdate;
    g_funcs.C_GenerateKey            = C_GenerateKey;
    g_funcs.C_GenerateKeyPair        = C_GenerateKeyPair;
    g_funcs.C_WrapKey                = C_WrapKey;
    g_funcs.C_UnwrapKey              = C_UnwrapKey;
    g_funcs.C_DeriveKey              = C_DeriveKey;
    g_funcs.C_SeedRandom             = C_SeedRandom;
    g_funcs.C_GenerateRandom         = C_GenerateRandom;
    g_funcs.C_GetFunctionStatus      = C_GetFunctionStatus;
    g_funcs.C_CancelFunction         = C_CancelFunction;
    g_funcs.C_WaitForSlotEvent       = C_WaitForSlotEvent;
}

