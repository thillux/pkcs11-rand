//! `p11rand-wait` — block until the PKCS#11 module reports a usable RNG.
//!
//! Loads the module, calls `C_Initialize`, then polls
//! `C_GetSlotList(tokenPresent=TRUE)` until the count rises to 1 — meaning
//! the pool is fillable (all configured N+M devices are present and
//! respond). Useful as a systemd `ExecStartPre` or shell gate.

#![allow(non_snake_case)]

use std::process::ExitCode;
use std::time::{Duration, Instant};

use p11rand_tools::cryptoki_sys::{CKR_OK, CK_TRUE, CK_ULONG};
use p11rand_tools::{install_signals, load_module, signal_count, signal_reset};

struct Args {
    timeout: Option<f64>, // seconds; None == wait forever
    poll_ms: u64,
    quiet: bool,
    module: String,
}

fn usage(argv0: &str) {
    eprintln!("usage: {argv0} [-t SECONDS] [-i POLL_MS] [-q] <module.so>");
    eprintln!("  -t SECONDS    give up after SECONDS (fractional OK); default: wait forever");
    eprintln!("  -i POLL_MS    poll interval, default 500");
    eprintln!("  -q            quiet; no informational stderr output");
}

fn parse() -> Result<Args, ExitCode> {
    let argv: Vec<String> = std::env::args().collect();
    let mut a = Args {
        timeout: None,
        poll_ms: 500,
        quiet: false,
        module: String::new(),
    };
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "-t" => {
                i += 1;
                let v: f64 = argv
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .ok_or(ExitCode::from(2))?;
                if v < 0.0 {
                    return Err(ExitCode::from(2));
                }
                a.timeout = Some(v);
            }
            "-i" => {
                i += 1;
                let v: u64 = argv
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .ok_or(ExitCode::from(2))?;
                if v == 0 {
                    return Err(ExitCode::from(2));
                }
                a.poll_ms = v;
            }
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

macro_rules! info {
    ($q:expr, $($t:tt)*) => {
        if !$q { eprintln!($($t)*); }
    };
}

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

    signal_reset();
    install_signals(false);

    if let Some(t) = a.timeout {
        info!(
            a.quiet,
            "waiting for PKCS#11 pool slot (poll={} ms, timeout={:.3} s)",
            a.poll_ms,
            t
        );
    } else {
        info!(
            a.quiet,
            "waiting for PKCS#11 pool slot (poll={} ms)",
            a.poll_ms
        );
    }

    let start = Instant::now();
    let interval = Duration::from_millis(a.poll_ms);
    let mut rv = ExitCode::from(1);
    loop {
        let mut count: CK_ULONG = 0;
        let r = unsafe { f.C_GetSlotList.unwrap()(CK_TRUE, std::ptr::null_mut(), &mut count) };
        if r == CKR_OK && count >= 1 {
            info!(
                a.quiet,
                "pool fillable after {:.2} s",
                start.elapsed().as_secs_f64()
            );
            rv = ExitCode::SUCCESS;
            break;
        }
        if signal_count() > 0 {
            info!(a.quiet, "interrupted by signal");
            break;
        }
        if let Some(t) = a.timeout {
            if start.elapsed().as_secs_f64() >= t {
                eprintln!("timeout after {:.2} s; pool not fillable", t);
                break;
            }
        }
        std::thread::sleep(interval);
    }

    unsafe {
        f.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    rv
}
