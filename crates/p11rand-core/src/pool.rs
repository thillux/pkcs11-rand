//! RNG pool — combines N iso7816 cards with M Infinite Noise TRNGs.
//!
//! Behavior summary (mirrors the original C [`rng.c`]):
//!
//! - `pool_size == 1` and no oversampling: raw passthrough — no SHA3
//!   post-processing, the session sees the source's bytes at full bandwidth.
//! - `pool_size >= 2` *or* any source oversampled (per-round bytes > 32):
//!   each output round is built by fetching `TICK_BYTES` (32) per source per
//!   tick in parallel and absorbing the results into a SHA3-256 chain
//!   analogous to infnoise's internal SHA3-512 chain:
//!
//!   ```text
//!   S_0     = 0^256
//!   E       = concat(per-tick fetches)
//!   output  = SHA3-256(S_i || 0x11 || E)
//!   S_{i+1} = SHA3-256(S_i || 0x00 || E)
//!   ```
//!
//! Removal/insertion is tolerated: per-source read failures are caught,
//! `rebind` is called on the failed slot, and the failed tick retries
//! serially. `rebind` opens a different reader/device that isn't already
//! held by another live slot. If no replacement is available, [`Pool::read`]
//! returns an error and the caller can retry later.

use std::thread;

use sha3::{Digest, Sha3_256};

use crate::{infnoise, iso7816, logd};

pub const TICK_BYTES: usize = 32;
pub const ROUND_BYTES: usize = 32;

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub iso7816_cards: usize,
    pub infnoise_devices: usize,
    /// Bytes fetched per iso7816 source per output round. Must be a multiple
    /// of 32. Setting it >32 forces the SHA3-256 chain on, even for n+m=1.
    pub iso7816_input_bytes: usize,
    /// Bytes fetched per infnoise source per output round. Must be a multiple
    /// of 32.
    pub infnoise_input_bytes: usize,
}

impl Config {
    pub const DEFAULT: Self = Self {
        iso7816_cards: 1,
        infnoise_devices: 0,
        iso7816_input_bytes: 32,
        infnoise_input_bytes: 32,
    };

    pub fn pool_size(&self) -> usize {
        self.iso7816_cards + self.infnoise_devices
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.pool_size() < 1 {
            return Err("Need at least one source: iso7816_cards or infnoise_devices >= 1");
        }
        if self.iso7816_cards > 0
            && (self.iso7816_input_bytes < 32 || !self.iso7816_input_bytes.is_multiple_of(32))
        {
            return Err("iso7816_input_bytes must be >= 32 and a multiple of 32");
        }
        if self.infnoise_devices > 0
            && (self.infnoise_input_bytes < 32
                || !self.infnoise_input_bytes.is_multiple_of(32))
        {
            return Err("infnoise_input_bytes must be >= 32 and a multiple of 32");
        }
        Ok(())
    }

    pub fn use_chain(&self) -> bool {
        let iso_oversampled = self.iso7816_cards > 0 && self.iso7816_input_bytes > 32;
        let inf_oversampled = self.infnoise_devices > 0 && self.infnoise_input_bytes > 32;
        self.pool_size() > 1 || iso_oversampled || inf_oversampled
    }

    pub fn slot_name(&self) -> String {
        if self.iso7816_cards > 0 && self.infnoise_devices > 0 {
            format!(
                "rng-pool[iso7816={},infnoise={}]",
                self.iso7816_cards, self.infnoise_devices
            )
        } else if self.iso7816_cards == 1 && self.infnoise_devices == 0 {
            "iso7816".to_string()
        } else if self.iso7816_cards > 0 {
            format!("rng-pool[iso7816={}]", self.iso7816_cards)
        } else if self.infnoise_devices == 1 {
            "infnoise".to_string()
        } else {
            format!("rng-pool[infnoise={}]", self.infnoise_devices)
        }
    }

    pub fn backend_label(&self) -> String {
        if !self.use_chain() {
            if self.iso7816_cards == 1 {
                "GET CHALLENGE RNG".into()
            } else {
                "Infinite Noise TRNG".into()
            }
        } else if self.iso7816_cards > 0 && self.infnoise_devices > 0 {
            format!(
                "{}x iso7816 + {}x inf + SHA3",
                self.iso7816_cards, self.infnoise_devices
            )
        } else if self.iso7816_cards > 0 {
            format!("{}x iso7816 + SHA3-256", self.iso7816_cards)
        } else {
            format!("{}x infnoise + SHA3-256", self.infnoise_devices)
        }
    }

    pub fn backend_model(&self) -> &'static str {
        if !self.use_chain() && self.iso7816_cards == 1 {
            "ISO7816-RNG"
        } else if !self.use_chain() {
            "INFNOISE"
        } else {
            "RNG-POOL"
        }
    }

    fn slot_ticks(&self, idx: usize) -> usize {
        if idx < self.iso7816_cards {
            self.iso7816_input_bytes / TICK_BYTES
        } else {
            self.infnoise_input_bytes / TICK_BYTES
        }
    }

    fn max_ticks(&self) -> usize {
        let iso = if self.iso7816_cards > 0 {
            self.iso7816_input_bytes / TICK_BYTES
        } else {
            0
        };
        let inf = if self.infnoise_devices > 0 {
            self.infnoise_input_bytes / TICK_BYTES
        } else {
            0
        };
        iso.max(inf)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SlotKind {
    Iso7816,
    Infnoise,
}

enum SlotInner {
    Iso7816(iso7816::Source),
    Infnoise(infnoise::Source),
    Empty,
}

struct Slot {
    kind: SlotKind,
    name: Option<String>,
    inner: SlotInner,
}

impl Slot {
    fn close(&mut self) {
        self.inner = SlotInner::Empty;
        self.name = None;
    }

    fn read(&mut self, buf: &mut [u8]) -> bool {
        match &mut self.inner {
            SlotInner::Iso7816(s) => s.read(buf).is_ok(),
            SlotInner::Infnoise(s) => s.read(buf).is_ok(),
            SlotInner::Empty => false,
        }
    }
}

#[derive(Debug)]
pub enum Error {
    /// Not enough usable sources right now (caller should retry).
    NotEnoughSources,
    /// Resource enumeration / allocation failure.
    Resource,
    /// Read failure that survived rebind retries.
    ReadFailure,
}

/// Initialize process-wide state for whichever backends the configured pool
/// uses. Idempotent across calls.
pub fn global_init(cfg: &Config) -> Result<(), Error> {
    if cfg.iso7816_cards > 0 {
        iso7816::global_init().map_err(|_| Error::Resource)?;
    }
    Ok(())
}

pub fn global_shutdown(cfg: &Config) {
    if cfg.iso7816_cards > 0 {
        iso7816::global_shutdown();
    }
}

/// Whether the pool can be filled right now from currently-available devices.
/// Returns `Ok(true)` for fillable, `Ok(false)` for not-enough-sources, `Err`
/// for transport/resource error.
pub fn fillable(cfg: &Config) -> Result<bool, Error> {
    if cfg.iso7816_cards > 0 {
        let readers = iso7816::list_readers().map_err(|_| Error::Resource)?;
        let mut usable = 0usize;
        for r in &readers {
            if usable >= cfg.iso7816_cards {
                break;
            }
            if iso7816::open(r).is_ok() {
                usable += 1;
            }
        }
        if usable < cfg.iso7816_cards {
            return Ok(false);
        }
    }
    if cfg.infnoise_devices > 0 {
        let paths = infnoise::list_paths().map_err(|_| Error::Resource)?;
        if paths.len() < cfg.infnoise_devices {
            return Ok(false);
        }
    }
    Ok(true)
}

pub struct Pool {
    config: Config,
    slots: Vec<Slot>,
    state: [u8; ROUND_BYTES],
}

impl Pool {
    /// Build the pool by claiming the first N readers and first M infnoise
    /// nodes that open successfully. Returns [`Error::NotEnoughSources`] if
    /// there aren't enough live devices right now.
    pub fn open(cfg: Config) -> Result<Self, Error> {
        cfg.validate().map_err(|_| Error::Resource)?;

        let mut slots: Vec<Slot> = Vec::with_capacity(cfg.pool_size());

        if cfg.iso7816_cards > 0 {
            let readers = iso7816::list_readers().map_err(|_| Error::Resource)?;
            for r in &readers {
                if slots.len() >= cfg.iso7816_cards {
                    break;
                }
                if let Ok(src) = iso7816::open(r) {
                    slots.push(Slot {
                        kind: SlotKind::Iso7816,
                        name: Some(r.clone()),
                        inner: SlotInner::Iso7816(src),
                    });
                }
            }
            if slots.len() < cfg.iso7816_cards {
                return Err(Error::NotEnoughSources);
            }
        }

        if cfg.infnoise_devices > 0 {
            let paths = infnoise::list_paths().map_err(|_| Error::Resource)?;
            let mut got = 0usize;
            for p in &paths {
                if got >= cfg.infnoise_devices {
                    break;
                }
                if let Ok(src) = infnoise::open(p) {
                    slots.push(Slot {
                        kind: SlotKind::Infnoise,
                        name: Some(p.clone()),
                        inner: SlotInner::Infnoise(src),
                    });
                    got += 1;
                }
            }
            if got < cfg.infnoise_devices {
                return Err(Error::NotEnoughSources);
            }
        }

        Ok(Self {
            config: cfg,
            slots,
            state: [0u8; ROUND_BYTES],
        })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    fn name_in_use(&self, skip: usize, kind: SlotKind, name: &str) -> bool {
        self.slots.iter().enumerate().any(|(j, s)| {
            j != skip
                && s.kind == kind
                && s.name.as_deref() == Some(name)
        })
    }

    fn rebind(&mut self, idx: usize) -> Result<(), Error> {
        let kind = self.slots[idx].kind;
        self.slots[idx].close();

        match kind {
            SlotKind::Iso7816 => {
                let readers = iso7816::list_readers().map_err(|_| Error::Resource)?;
                for r in &readers {
                    if self.name_in_use(idx, kind, r) {
                        continue;
                    }
                    if let Ok(src) = iso7816::open(r) {
                        self.slots[idx] = Slot {
                            kind,
                            name: Some(r.clone()),
                            inner: SlotInner::Iso7816(src),
                        };
                        logd!("pool", "rebound slot {} -> {}", idx, r);
                        return Ok(());
                    }
                }
            }
            SlotKind::Infnoise => {
                let paths = infnoise::list_paths().map_err(|_| Error::Resource)?;
                for p in &paths {
                    if self.name_in_use(idx, kind, p) {
                        continue;
                    }
                    if let Ok(src) = infnoise::open(p) {
                        self.slots[idx] = Slot {
                            kind,
                            name: Some(p.clone()),
                            inner: SlotInner::Infnoise(src),
                        };
                        logd!("pool", "rebound slot {} -> {}", idx, p);
                        return Ok(());
                    }
                }
            }
        }
        logd!("pool", "rebind slot {}: no usable replacement", idx);
        Err(Error::NotEnoughSources)
    }

    pub fn read(&mut self, mut buf: &mut [u8]) -> Result<(), Error> {
        if self.config.use_chain() {
            let mut out = [0u8; ROUND_BYTES];
            while !buf.is_empty() {
                self.do_round_chain(&mut out)?;
                let take = buf.len().min(ROUND_BYTES);
                buf[..take].copy_from_slice(&out[..take]);
                buf = &mut buf[take..];
            }
            // Wipe round scratch.
            for b in out.iter_mut() {
                *b = 0;
            }
            Ok(())
        } else {
            // Single source, no oversampling: raw passthrough with one
            // rebind retry on transport failure.
            if self.slots[0].read(buf) {
                return Ok(());
            }
            logd!(
                "pool",
                "source 0 ({}) failed; rebinding",
                self.slots[0].name.as_deref().unwrap_or("?")
            );
            self.rebind(0)?;
            if self.slots[0].read(buf) {
                Ok(())
            } else {
                Err(Error::ReadFailure)
            }
        }
    }

    /// Build one [`ROUND_BYTES`] output round.
    ///
    /// Per round we run `MAX_TICKS` ticks. On each tick we spawn one worker
    /// per source whose own quota for the round is not yet exhausted; each
    /// worker fetches exactly [`TICK_BYTES`] into a 32-byte scratch. We
    /// join in slot index order and absorb each scratch into both SHA3-256
    /// contexts (output, state-update) immediately, in slot order, then
    /// proceed to the next tick. Sources that fail mid-round are rebound
    /// and the failed tick retried serially before moving on.
    ///
    /// Absorption order is tick-major (matches the C version):
    ///
    /// ```text
    /// E_round = concat over t in 0..MAX_TICKS-1
    ///              over slot i in 0..pool_size-1 with slot_ticks(i) > t
    ///              of the t-th 32-byte fetch from slot i
    /// ```
    fn do_round_chain(&mut self, out: &mut [u8; ROUND_BYTES]) -> Result<(), Error> {
        let mut h_out = Sha3_256::new();
        let mut h_state = Sha3_256::new();
        h_out.update(self.state);
        h_state.update(self.state);
        h_out.update([0x11u8]);
        h_state.update([0x00u8]);

        let pool_size = self.slots.len();
        let max_ticks = self.config.max_ticks();
        let cfg = self.config;

        for t in 0..max_ticks {
            // Per-slot scratch for this tick. `None` means "this slot owed
            // bytes but its read failed and we still need to recover".
            let mut scratch: Vec<Option<[u8; TICK_BYTES]>> = vec![None; pool_size];

            // Fan out: one worker per source still owing bytes this round.
            // We use `thread::scope` so each worker can borrow its slot's
            // mutable state for the duration of the tick.
            thread::scope(|s| {
                let mut handles: Vec<(usize, _)> = Vec::with_capacity(pool_size);
                for (i, slot) in self.slots.iter_mut().enumerate() {
                    if t >= cfg.slot_ticks(i) {
                        continue;
                    }
                    let h = s.spawn(move || {
                        let mut buf = [0u8; TICK_BYTES];
                        let ok = slot.read(&mut buf);
                        (ok, buf)
                    });
                    handles.push((i, h));
                }
                for (i, h) in handles {
                    let (ok, buf) = h.join().expect("worker panicked");
                    if ok {
                        scratch[i] = Some(buf);
                    }
                }
            });

            // Absorb in slot index order. Slots that failed get rebound and
            // retried serially before we move on. (Index loop instead of
            // `enumerate`-on-`scratch`: the body also needs `&mut self` for
            // `rebind`, which would conflict with an outstanding iter_mut.)
            #[allow(clippy::needless_range_loop)]
            for i in 0..pool_size {
                if t >= cfg.slot_ticks(i) {
                    continue;
                }
                if scratch[i].is_none() {
                    logd!(
                        "pool",
                        "source {} ({}) tick {} failed; rebinding",
                        i,
                        self.slots[i].name.as_deref().unwrap_or("?"),
                        t
                    );
                    self.rebind(i)?;
                    let mut buf = [0u8; TICK_BYTES];
                    if !self.slots[i].read(&mut buf) {
                        return Err(Error::ReadFailure);
                    }
                    scratch[i] = Some(buf);
                }
                let buf = scratch[i].as_ref().unwrap();
                h_out.update(buf);
                h_state.update(buf);
            }
        }

        let out_digest = h_out.finalize();
        out.copy_from_slice(&out_digest);

        let state_digest = h_state.finalize();
        self.state.copy_from_slice(&state_digest);
        Ok(())
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        // Wipe the chain state so a freed Pool's last round doesn't sit on
        // the heap.
        for b in self.state.iter_mut() {
            *b = 0;
        }
    }
}
