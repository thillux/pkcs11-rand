//! Infinite Noise TRNG source: thin wrapper around `/dev/infnoiseN`.
//!
//! The kernel-side driver owns the FT240X transport, the sync bit-bang, and
//! the running health monitor; userspace just open(2)s the char node and
//! pulls post-health-check bytes via read(2). Multiple independent contexts
//! coexist in one process; per-device state lives entirely in [`Source`].

use std::fs::File;
use std::io::{ErrorKind, Read};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::logd;

const DEV_DIR: &str = "/dev";
const DEV_PREFIX: &str = "infnoise";

#[derive(Debug)]
pub enum Error {
    /// Device absent / not openable.
    NoDevice,
    /// I/O failure once opened.
    Io,
}

/// Enumerate `/dev/infnoiseN` nodes currently exposed by the kernel, in
/// numeric order. Returns an empty vector when none are present.
pub fn list_paths() -> Result<Vec<String>, Error> {
    let entries = match std::fs::read_dir(DEV_DIR) {
        Ok(it) => it,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            eprintln!("p11rand[infnoise]: {DEV_DIR}: {e}");
            return Err(Error::Io);
        }
    };

    let mut out: Vec<(u64, PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let bytes = name.as_bytes();
        if !bytes.starts_with(DEV_PREFIX.as_bytes()) {
            continue;
        }
        let suffix = &bytes[DEV_PREFIX.len()..];
        if suffix.is_empty() || !suffix.iter().all(|b| b.is_ascii_digit()) {
            continue;
        }
        // Safe: ASCII digits parse as u64.
        let idx: u64 = std::str::from_utf8(suffix).unwrap().parse().unwrap_or(0);
        out.push((idx, entry.path()));
    }
    out.sort_by_key(|(i, _)| *i);
    Ok(out
        .into_iter()
        .map(|(_, p)| p.to_string_lossy().into_owned())
        .collect())
}

pub struct Source {
    file: File,
    #[allow(dead_code)]
    path: String,
}

pub fn open(path: &str) -> Result<Source, Error> {
    open_path(Path::new(path))
}

pub fn open_first() -> Result<Source, Error> {
    let paths = list_paths().map_err(|_| Error::NoDevice)?;
    let first = paths.first().ok_or_else(|| {
        eprintln!("p11rand[infnoise]: no /dev/{DEV_PREFIX}N nodes available");
        Error::NoDevice
    })?;
    open_path(Path::new(first))
}

fn open_path(path: &Path) -> Result<Source, Error> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|e| {
            logd!("infnoise", "open {}: {}", path.display(), e);
            Error::NoDevice
        })?;
    let path = path.to_string_lossy().into_owned();
    logd!("infnoise", "opened {}", path);
    Ok(Source { file, path })
}

impl Source {
    pub fn read(&mut self, mut buf: &mut [u8]) -> Result<(), Error> {
        while !buf.is_empty() {
            match self.file.read(buf) {
                Ok(0) => {
                    eprintln!(
                        "p11rand[infnoise]: {}: unexpected EOF",
                        self.path
                    );
                    return Err(Error::Io);
                }
                Ok(n) => {
                    buf = &mut buf[n..];
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => {
                    eprintln!("p11rand[infnoise]: {}: {}", self.path, e);
                    return Err(Error::Io);
                }
            }
        }
        Ok(())
    }
}
