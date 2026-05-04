//! `p11rand-seed` — seed the Linux kernel RNG from a PKCS#11 module.
//!
//! Periodically calls `C_GenerateRandom` for N bytes and pushes them into
//! `/dev/random`. By default the insertion uses the `RNDADDENTROPY` ioctl,
//! which both mixes the bytes in *and* credits N*8 bits of entropy to the
//! kernel pool — that requires `CAP_SYS_ADMIN` (typically root). Pass
//! `--no-credit` to fall back to a plain write(2) (no entropy credit).
//!
//! After each successful credit the seeder also issues `RNDRESEEDCRNG`,
//! forcing the kernel CRNG to mix the new entropy in immediately. Both
//! ioctls share the `CAP_SYS_ADMIN` requirement; either falls back
//! gracefully if the kernel returns `EPERM`.

#![allow(non_snake_case)]

use std::ffi::c_int;
use std::fs::OpenOptions;
use std::io::Write;
use std::mem::size_of;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use p11rand_tools::cryptoki_sys::{
    CKF_SERIAL_SESSION, CKR_OK, CK_SESSION_HANDLE, CK_SLOT_ID, CK_TRUE, CK_ULONG,
};
use p11rand_tools::{install_signals, load_module, signal_count, signal_reset};

const DEFAULT_INTERVAL: f64 = 60.0;
const DEFAULT_NBYTES: usize = 64;
const MAX_NBYTES: usize = 4096;

// `/usr/include/linux/random.h`:
//   #define RNDADDENTROPY  _IOW('R', 0x03, int[2])
//   #define RNDRESEEDCRNG  _IO ('R', 0x07)
// Both ioctl numbers are stable across the kernels we care about.
const RNDADDENTROPY: libc::c_ulong = 0x4008_5203;
const RNDRESEEDCRNG: libc::c_ulong = 0x0000_5207;

#[repr(C)]
struct RandPoolInfoHeader {
    entropy_count: c_int,
    buf_size: c_int,
    // `__u32 buf[0]` flex array follows in memory.
}

struct Args {
    interval: f64,
    nbytes: usize,
    no_credit: bool,
    no_reseed: bool,
    quiet: bool,
    module: String,
}

fn usage(argv0: &str) {
    eprintln!(
        "usage: {argv0} [-t SECONDS] [-n BYTES] [--no-credit] [--no-reseed] [-q] <module.so>"
    );
    eprintln!("  -t SECONDS    interval between insertions (fractional OK); default 60");
    eprintln!("  -n BYTES      bytes per insertion (1..{MAX_NBYTES}); default {DEFAULT_NBYTES}");
    eprintln!("  --no-credit   plain write(2) instead of RNDADDENTROPY (no root needed)");
    eprintln!("  --no-reseed   skip RNDRESEEDCRNG after each successful credit");
    eprintln!("  -q            quiet; no informational stderr output");
}

fn parse() -> Result<Args, ExitCode> {
    let argv: Vec<String> = std::env::args().collect();
    let mut a = Args {
        interval: DEFAULT_INTERVAL,
        nbytes: DEFAULT_NBYTES,
        no_credit: false,
        no_reseed: false,
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
                if v <= 0.0 {
                    return Err(ExitCode::from(2));
                }
                a.interval = v;
            }
            "-n" => {
                i += 1;
                let v: usize = argv
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .ok_or(ExitCode::from(2))?;
                if v == 0 || v > MAX_NBYTES {
                    return Err(ExitCode::from(2));
                }
                a.nbytes = v;
            }
            "--no-credit" => a.no_credit = true,
            "--no-reseed" => a.no_reseed = true,
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

fn interruptible_sleep(seconds: f64) {
    if seconds <= 0.0 {
        return;
    }
    // Wake periodically (50ms) so we notice signal_count() going up promptly.
    let total = Duration::from_secs_f64(seconds);
    let start = Instant::now();
    let tick = Duration::from_millis(50);
    while start.elapsed() < total && signal_count() == 0 {
        let remaining = total.saturating_sub(start.elapsed());
        std::thread::sleep(remaining.min(tick));
    }
}

fn main() -> ExitCode {
    let mut a = match parse() {
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

    let mut sess: CK_SESSION_HANDLE = 0;
    let rv = unsafe {
        f.C_OpenSession.unwrap()(
            slots[0],
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

    let mut rfile = match OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_CLOEXEC)
        .open("/dev/random")
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("open /dev/random: {e}");
            unsafe {
                f.C_CloseSession.unwrap()(sess);
                f.C_Finalize.unwrap()(std::ptr::null_mut());
            }
            return ExitCode::from(1);
        }
    };

    // One contiguous allocation: rand_pool_info header followed by the byte
    // buffer. C_GenerateRandom writes straight into the buf area;
    // RNDADDENTROPY consumes the same memory.
    let header_size = size_of::<RandPoolInfoHeader>();
    let total = header_size + a.nbytes;
    let mut blob = vec![0u8; total];
    {
        let hdr = unsafe { &mut *(blob.as_mut_ptr() as *mut RandPoolInfoHeader) };
        hdr.entropy_count = (a.nbytes * 8) as c_int;
        hdr.buf_size = a.nbytes as c_int;
    }

    signal_reset();
    install_signals(false);

    info!(
        a.quiet,
        "seeding /dev/random: {} B every {:.2} s{}",
        a.nbytes,
        a.interval,
        if a.no_credit { " (no entropy credit)" } else { "" }
    );

    while signal_count() == 0 {
        let buf_ptr = unsafe { blob.as_mut_ptr().add(header_size) };
        let rv = unsafe { f.C_GenerateRandom.unwrap()(sess, buf_ptr, a.nbytes as CK_ULONG) };
        if rv != CKR_OK {
            if signal_count() > 0 {
                break;
            }
            eprintln!("C_GenerateRandom failed; retrying after interval");
            interruptible_sleep(a.interval);
            continue;
        }

        if a.no_credit {
            let buf = unsafe { std::slice::from_raw_parts(buf_ptr, a.nbytes) };
            match rfile.write(buf) {
                Ok(n) => info!(a.quiet, "wrote {n} B (uncredited)"),
                Err(e) => eprintln!("write /dev/random: {e}"),
            }
        } else {
            let r = unsafe {
                libc::ioctl(
                    rfile.as_raw_fd(),
                    RNDADDENTROPY,
                    blob.as_ptr() as *const libc::c_void,
                )
            };
            if r < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EPERM) {
                    eprintln!(
                        "RNDADDENTROPY: EPERM — falling back to uncredited write \
                         (run as root or with CAP_SYS_ADMIN to credit entropy)"
                    );
                    a.no_credit = true;
                    let buf = unsafe { std::slice::from_raw_parts(buf_ptr, a.nbytes) };
                    if let Err(e) = rfile.write(buf) {
                        eprintln!("write /dev/random: {e}");
                    }
                } else {
                    eprintln!("RNDADDENTROPY: {err}");
                }
            } else {
                info!(a.quiet, "credited {} B ({} bits) to kernel pool", a.nbytes, a.nbytes * 8);
                if !a.no_reseed {
                    let r = unsafe { libc::ioctl(rfile.as_raw_fd(), RNDRESEEDCRNG) };
                    if r < 0 {
                        let err = std::io::Error::last_os_error();
                        if err.raw_os_error() == Some(libc::EPERM) {
                            eprintln!("RNDRESEEDCRNG: EPERM — disabling for the run");
                            a.no_reseed = true;
                        } else {
                            eprintln!("RNDRESEEDCRNG: {err}");
                        }
                    } else {
                        info!(a.quiet, "forced CRNG reseed");
                    }
                }
            }
        }

        interruptible_sleep(a.interval);
    }

    info!(a.quiet, "exiting");

    // Don't leave the byte buffer in memory after exit.
    blob.fill(0);

    unsafe {
        f.C_CloseSession.unwrap()(sess);
        f.C_Finalize.unwrap()(std::ptr::null_mut());
    }
    ExitCode::SUCCESS
}
