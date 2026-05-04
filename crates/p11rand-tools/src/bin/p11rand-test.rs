//! Tiny CLI driver: dlopen the module, list slots, ask the first slot's
//! token for 32 random bytes, dump them as hex.
//!
//! Usage: `p11rand-test ./libp11rand.so [byte_count]`

#![allow(non_snake_case)]

use std::process::ExitCode;

use p11rand_tools::cryptoki_sys::{self, *};
use p11rand_tools::{load_module, trim_pkcs11};

fn die(what: &str, rv: CK_RV) -> ! {
    eprintln!("{what} failed: 0x{rv:x}");
    std::process::exit(2);
}

fn show_field(label: &str, field: &[u8]) {
    println!("  {label:<12} {}", trim_pkcs11(field));
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: {} <module.so> [nbytes]", args[0]);
        return ExitCode::from(1);
    }
    let n: usize = if args.len() >= 3 {
        args[2].parse().unwrap_or(32)
    } else {
        32
    };

    let m = match load_module(&args[1]) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let f = m.funcs;
    unsafe {
        let rv = f.C_Initialize.unwrap()(std::ptr::null_mut());
        if rv != CKR_OK {
            die("C_Initialize", rv);
        }

        // Enumerate every reader (tokenPresent=false) so we can show empty
        // slots; then enumerate again with tokenPresent=true to pick a slot
        // whose token is actually usable.
        let mut nall: CK_ULONG = 0;
        let rv = f.C_GetSlotList.unwrap()(CK_FALSE, std::ptr::null_mut(), &mut nall);
        if rv != CKR_OK {
            die("C_GetSlotList(size, all)", rv);
        }
        let mut all: Vec<CK_SLOT_ID> = vec![0; nall as usize];
        if nall > 0 {
            let rv = f.C_GetSlotList.unwrap()(CK_FALSE, all.as_mut_ptr(), &mut nall);
            if rv != CKR_OK {
                die("C_GetSlotList(all)", rv);
            }
            all.truncate(nall as usize);
        }

        println!("readers visible: {}", nall);
        for &slot in &all {
            let mut si: CK_SLOT_INFO = std::mem::zeroed();
            if f.C_GetSlotInfo.unwrap()(slot, &mut si) != CKR_OK {
                continue;
            }
            let mark = if (si.flags & cryptoki_sys::CKF_TOKEN_PRESENT) != 0 {
                "[token]"
            } else {
                "[empty]"
            };
            println!("[{slot}] {mark} flags=0x{:x}", si.flags);
            show_field("reader", &si.slotDescription);
        }

        let mut nuse: CK_ULONG = 0;
        let rv = f.C_GetSlotList.unwrap()(CK_TRUE, std::ptr::null_mut(), &mut nuse);
        if rv != CKR_OK {
            die("C_GetSlotList(size, present)", rv);
        }
        if nuse == 0 {
            eprintln!("no usable token in any reader");
            f.C_Finalize.unwrap()(std::ptr::null_mut());
            return ExitCode::from(3);
        }
        let mut use_slots: Vec<CK_SLOT_ID> = vec![0; nuse as usize];
        let rv = f.C_GetSlotList.unwrap()(CK_TRUE, use_slots.as_mut_ptr(), &mut nuse);
        if rv != CKR_OK {
            die("C_GetSlotList(present)", rv);
        }

        let picked = use_slots[0];
        println!(
            "using slot {} (first with a usable token, of {})",
            picked, nuse
        );

        let mut sess: CK_SESSION_HANDLE = 0;
        let rv = f.C_OpenSession.unwrap()(
            picked,
            CKF_SERIAL_SESSION,
            std::ptr::null_mut(),
            None,
            &mut sess,
        );
        if rv != CKR_OK {
            die("C_OpenSession", rv);
        }

        let mut ti: CK_TOKEN_INFO = std::mem::zeroed();
        if f.C_GetTokenInfo.unwrap()(picked, &mut ti) == CKR_OK {
            println!("token:");
            show_field("label", &ti.label);
            show_field("model", &ti.model);
            show_field("mfr", &ti.manufacturerID);
            println!("  flags        0x{:x}", ti.flags);
        }

        let mut buf = vec![0u8; n];
        let rv = f.C_GenerateRandom.unwrap()(sess, buf.as_mut_ptr(), n as CK_ULONG);
        if rv != CKR_OK {
            die("C_GenerateRandom", rv);
        }

        print!("random[{n}]: ");
        for b in &buf {
            print!("{b:02x}");
        }
        println!();

        f.C_CloseSession.unwrap()(sess);
        f.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    ExitCode::SUCCESS
}
