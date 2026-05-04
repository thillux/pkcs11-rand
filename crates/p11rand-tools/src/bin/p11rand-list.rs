//! `p11rand-list` — inventory of TRNG sources visible on this host.
//!
//! Probes every PC/SC reader for a card that responds to GET CHALLENGE (the
//! iso7816 backend's usability test) and every `/dev/infnoiseN` node exposed
//! by the in-kernel Infinite Noise driver. The output is independent of the
//! pool configuration baked into the cdylib — useful for picking sensible
//! `P11RAND_ISO7816_CARDS` / `P11RAND_INFNOISE_DEVICES` values, debugging
//! missing permissions, or sanity-checking before starting the seeder.
//!
//! Probe semantics:
//!   - iso7816: SCardConnect(SHARE_SHARED) + select-and-GET-CHALLENGE
//!     handshake. SHARE_SHARED is intentional — a passing probe doesn't
//!     kick out other PKCS#11 consumers.
//!   - infnoise: open(2) the `/dev/infnoiseN` node via the source layer.

use std::process::ExitCode;

use p11rand_core::{infnoise, iso7816};

struct Args {
    quiet: bool,
    verbose: bool,
}

fn parse_args() -> Result<Args, ExitCode> {
    let mut a = Args { quiet: false, verbose: false };
    let argv: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "-q" => a.quiet = true,
            "-v" => a.verbose = true,
            "-h" | "--help" => {
                eprintln!("usage: {} [-q] [-v]", argv[0]);
                eprintln!("  -q    tab-separated output (kind\\tname\\tstatus); no headings");
                eprintln!(
                    "  -v    verbose: per-APDU / USB trace from the source layers \
                     (P11RAND_DEBUG=1)"
                );
                return Err(ExitCode::from(0));
            }
            _ => {
                eprintln!("usage: {} [-q] [-v]", argv[0]);
                return Err(ExitCode::from(2));
            }
        }
        i += 1;
    }
    Ok(a)
}

fn emit(quiet: bool, kind: &str, name: &str, status: &str, extra: &str) {
    let has_extra = !extra.is_empty();
    if quiet {
        if has_extra {
            println!("{kind}\t{name}\t{status}\t{extra}");
        } else {
            println!("{kind}\t{name}\t{status}");
        }
    } else if has_extra {
        println!("  [{status:<8}] {name}  ({extra})");
    } else {
        println!("  [{status:<8}] {name}");
    }
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(c) => return c,
    };

    if args.verbose {
        // The source layers read this at global_init time. Setting it now,
        // before the init calls below, is enough.
        std::env::set_var("P11RAND_DEBUG", "1");
    }

    let mut iso_total = 0u32;
    let mut iso_usable = 0u32;
    let mut inf_total = 0u32;
    let mut inf_usable = 0u32;

    // ----- iso7816 / PC/SC --------------------------------------------------
    match iso7816::global_init() {
        Ok(()) => {
            match iso7816::list_readers() {
                Ok(readers) => {
                    iso_total = readers.len() as u32;
                    if !readers.is_empty() && !args.quiet {
                        println!("iso7816 (PC/SC):");
                    }
                    for r in &readers {
                        let (status, has_card) = match iso7816::open(r) {
                            Ok(_src) => {
                                iso_usable += 1;
                                ("usable", true)
                            }
                            Err(iso7816::Error::NoCard) => ("no-card", false),
                            Err(iso7816::Error::Unsupported) => ("unsupported", true),
                            Err(_) => ("error", false),
                        };
                        // Annotate every slot that actually has a card with
                        // its ATR — gives the user something to grep against
                        // an ATR database when a card is rejected.
                        let extra = if has_card {
                            iso7816::read_atr(r)
                                .map(|a| format!("ATR={a}"))
                                .unwrap_or_default()
                        } else {
                            String::new()
                        };
                        emit(args.quiet, "iso7816", r, status, &extra);
                    }
                }
                Err(_) if !args.quiet => {
                    eprintln!("iso7816: enumeration failed");
                }
                Err(_) => {}
            }
            iso7816::global_shutdown();
        }
        Err(_) if !args.quiet => {
            eprintln!("iso7816: PC/SC context init failed (is pcscd running?)");
        }
        Err(_) => {}
    }

    // ----- infnoise / /dev/infnoiseN ---------------------------------------
    match infnoise::list_paths() {
        Ok(paths) => {
            inf_total = paths.len() as u32;
            if !paths.is_empty() && !args.quiet {
                if iso_total > 0 {
                    println!();
                }
                println!("infnoise (/dev/infnoiseN):");
            }
            for p in &paths {
                let status = match infnoise::open(p) {
                    Ok(_) => {
                        inf_usable += 1;
                        "usable"
                    }
                    Err(_) => "unusable",
                };
                emit(args.quiet, "infnoise", p, status, "");
            }
        }
        Err(_) if !args.quiet => {
            eprintln!("infnoise: enumeration failed");
        }
        Err(_) => {}
    }

    if !args.quiet {
        if iso_total + inf_total == 0 {
            println!("(no PC/SC readers and no FT240X devices found)");
        } else {
            println!(
                "\nsummary: iso7816 {iso_usable}/{iso_total} usable, \
                 infnoise {inf_usable}/{inf_total} usable"
            );
        }
    }

    if iso_usable + inf_usable > 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
