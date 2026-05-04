//! `p11rand-read` — pipe random bytes from a PKCS#11 module to stdout.
//!
//! Loads the module, opens a session on the first usable slot, and writes
//! the result of `C_GenerateRandom` to stdout. Default 32 bytes raw; -n N
//! for a specific length, -n 0 for an open-ended stream (until SIGINT or
//! stdout closes), -x for lowercase hex output.
//!
//! Cancellation: the first SIGINT/SIGTERM lets the current 256-byte
//! C_GenerateRandom finish and then exits cleanly. A second signal short-
//! circuits with `_exit(130)`.

#![allow(non_snake_case)]

use std::io::{self, ErrorKind, Write};
use std::process::ExitCode;

use p11rand_tools::cryptoki_sys::{
    CKF_SERIAL_SESSION, CKR_OK, CK_SESSION_HANDLE, CK_SLOT_ID, CK_TRUE, CK_ULONG,
};
use p11rand_tools::{install_signals, load_module, signal_count, signal_reset};

struct Args {
    n_total: i64, // -1 = open-ended stream
    hex: bool,
    quiet: bool,
    module: String,
}

fn usage(argv0: &str) {
    eprintln!("usage: {argv0} [-n BYTES] [-x] [-q] <module.so>");
    eprintln!("  -n BYTES   total bytes to output; default 32; 0 = open-ended stream");
    eprintln!("  -x         lowercase hex output (one continuous string + newline)");
    eprintln!("  -q         quiet — no informational stderr");
}

fn parse() -> Result<Args, ExitCode> {
    let argv: Vec<String> = std::env::args().collect();
    let mut a = Args { n_total: 32, hex: false, quiet: false, module: String::new() };
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "-n" => {
                i += 1;
                let v: i64 = argv
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .ok_or(ExitCode::from(2))?;
                if v < 0 {
                    return Err(ExitCode::from(2));
                }
                a.n_total = if v == 0 { -1 } else { v };
            }
            "-x" => a.hex = true,
            "-q" => a.quiet = true,
            "-h" | "--help" => {
                usage(&argv[0]);
                return Err(ExitCode::from(0));
            }
            s if !s.starts_with('-') => {
                a.module = s.to_string();
                if i + 1 < argv.len() {
                    return Err(ExitCode::from(2));
                }
            }
            _ => {
                usage(&argv[0]);
                return Err(ExitCode::from(2));
            }
        }
        i += 1;
    }
    if a.module.is_empty() {
        usage(&argv[0]);
        return Err(ExitCode::from(2));
    }
    Ok(a)
}

fn write_full(out: &mut impl Write, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        match out.write(buf) {
            Ok(0) => return Err(io::Error::new(ErrorKind::WriteZero, "write zero")),
            Ok(n) => buf = &buf[n..],
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn write_hex(out: &mut impl Write, buf: &[u8]) -> io::Result<()> {
    let mut tmp = [0u8; 1024];
    let mut off = 0usize;
    for &b in buf {
        if off + 2 > tmp.len() {
            write_full(out, &tmp[..off])?;
            off = 0;
        }
        tmp[off] = HEX[(b >> 4) as usize];
        tmp[off + 1] = HEX[(b & 0xf) as usize];
        off += 2;
    }
    if off > 0 {
        write_full(out, &tmp[..off])?;
    }
    Ok(())
}

const HEX: [u8; 16] = *b"0123456789abcdef";

fn main() -> ExitCode {
    let a = match parse() {
        Ok(a) => a,
        Err(c) => return c,
    };

    let m = match load_module(&a.module) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let f = m.funcs;

    unsafe {
        if f.C_Initialize.unwrap()(std::ptr::null_mut()) != CKR_OK {
            eprintln!("C_Initialize failed");
            return ExitCode::from(2);
        }
    }

    let mut nslots: CK_ULONG = 0;
    let rv = unsafe { f.C_GetSlotList.unwrap()(CK_TRUE, std::ptr::null_mut(), &mut nslots) };
    if rv != CKR_OK || nslots == 0 {
        eprintln!("no usable PKCS#11 slot — pool not fillable yet?");
        unsafe { f.C_Finalize.unwrap()(std::ptr::null_mut()) };
        return ExitCode::from(1);
    }
    let mut slots: Vec<CK_SLOT_ID> = vec![0; nslots as usize];
    let rv = unsafe { f.C_GetSlotList.unwrap()(CK_TRUE, slots.as_mut_ptr(), &mut nslots) };
    if rv != CKR_OK {
        eprintln!("C_GetSlotList failed");
        unsafe { f.C_Finalize.unwrap()(std::ptr::null_mut()) };
        return ExitCode::from(1);
    }
    let slot = slots[0];

    let mut sess: CK_SESSION_HANDLE = 0;
    let rv = unsafe {
        f.C_OpenSession.unwrap()(
            slot,
            CKF_SERIAL_SESSION,
            std::ptr::null_mut(),
            None,
            &mut sess,
        )
    };
    if rv != CKR_OK {
        eprintln!("C_OpenSession failed");
        unsafe { f.C_Finalize.unwrap()(std::ptr::null_mut()) };
        return ExitCode::from(1);
    }

    signal_reset();
    install_signals(true);

    if a.n_total < 0 {
        if !a.quiet {
            eprintln!(
                "p11rand-read: streaming {} output (Ctrl-C to stop)",
                if a.hex { "hex" } else { "raw" }
            );
        }
    } else if !a.quiet {
        eprintln!(
            "p11rand-read: {} bytes ({})",
            a.n_total,
            if a.hex { "hex" } else { "raw" }
        );
    }

    // Per-call request is intentionally small so SIGINT / SIGTERM take
    // effect within a few hundred milliseconds even during long streams.
    let mut buf = [0u8; 256];
    let mut exit_rv = ExitCode::SUCCESS;
    let mut produced: i64 = 0;
    let mut stdout = io::stdout().lock();

    while signal_count() == 0 && (a.n_total < 0 || produced < a.n_total) {
        let mut want = buf.len();
        if a.n_total >= 0 && (want as i64) > a.n_total - produced {
            want = (a.n_total - produced) as usize;
        }

        let rv = unsafe {
            f.C_GenerateRandom.unwrap()(sess, buf.as_mut_ptr(), want as CK_ULONG)
        };
        if rv != CKR_OK {
            if signal_count() > 0 {
                break;
            }
            eprintln!("C_GenerateRandom failed");
            exit_rv = ExitCode::from(1);
            break;
        }
        if signal_count() > 0 {
            break;
        }

        let res = if a.hex {
            write_hex(&mut stdout, &buf[..want])
        } else {
            write_full(&mut stdout, &buf[..want])
        };
        match res {
            Ok(()) => {
                produced += want as i64;
            }
            Err(e) if e.kind() == ErrorKind::BrokenPipe => break,
            Err(e) => {
                eprintln!("write: {e}");
                exit_rv = ExitCode::from(1);
                break;
            }
        }
    }

    if a.hex && produced > 0 {
        let _ = stdout.write_all(b"\n");
    }
    drop(stdout);

    unsafe {
        f.C_CloseSession.unwrap()(sess);
        f.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    // Wipe the buffer so the last cycle's bytes don't sit on the stack.
    buf.fill(0);
    exit_rv
}
