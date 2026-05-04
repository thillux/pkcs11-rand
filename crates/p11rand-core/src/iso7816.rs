//! iso7816 source: PC/SC + ISO 7816-4 GET CHALLENGE.
//!
//! Each [`Source`] wraps one PC/SC card connection whose default applet (PIV,
//! OpenPGP, or bare card) responds to GET CHALLENGE. The PC/SC user context is
//! process-wide and refcounted across multiple sessions; SCardConnect /
//! SCardTransmit can run concurrently across threads as long as each holds its
//! own card handle, which is what the pool arranges (one source per round).

use std::ffi::{CStr, CString};
use std::sync::{Mutex, OnceLock};

use pcsc::{
    Card, Context, Disposition, Error as PcscError, Protocols, Scope, ShareMode,
};

use crate::logd;

#[derive(Debug)]
pub enum Error {
    /// Reader has no card / removed / unresponsive / unpowered.
    NoCard,
    /// Card present, but no GET-CHALLENGE-capable applet on default/PIV/OpenPGP.
    Unsupported,
    /// Anything else: transport, PC/SC service down, etc.
    Transport,
}

struct Global {
    ctx: Option<Context>,
    refs: usize,
}

fn global() -> &'static Mutex<Global> {
    static G: OnceLock<Mutex<Global>> = OnceLock::new();
    G.get_or_init(|| Mutex::new(Global { ctx: None, refs: 0 }))
}

pub fn global_init() -> Result<(), Error> {
    let mut g = global().lock().unwrap();
    if g.refs > 0 {
        g.refs += 1;
        return Ok(());
    }
    let ctx = Context::establish(Scope::User).map_err(|e| {
        eprintln!("p11rand[iso7816]: SCardEstablishContext failed: {e:?}");
        Error::Transport
    })?;
    g.ctx = Some(ctx);
    g.refs = 1;
    Ok(())
}

pub fn global_shutdown() {
    let mut g = global().lock().unwrap();
    if g.refs == 0 {
        return;
    }
    g.refs -= 1;
    if g.refs == 0 {
        // Drop the Context; pcsc::Context::Drop calls SCardReleaseContext.
        g.ctx = None;
    }
}

fn with_context<R, F>(f: F) -> Result<R, Error>
where
    F: FnOnce(&Context) -> Result<R, Error>,
{
    let g = global().lock().unwrap();
    let ctx = g.ctx.as_ref().ok_or(Error::Transport)?;
    f(ctx)
}

/// Enumerate PC/SC reader names.
pub fn list_readers() -> Result<Vec<String>, Error> {
    with_context(|ctx| {
        let len = ctx.list_readers_len().map_err(|e| {
            // No readers attached at all is success-with-empty, not an error.
            if matches!(e, PcscError::NoReadersAvailable) {
                return Error::Transport; // sentinel; mapped below
            }
            eprintln!("p11rand[iso7816]: SCardListReaders(size) failed: {e:?}");
            Error::Transport
        });
        let len = match len {
            Ok(n) => n,
            Err(_) => return Ok(Vec::new()),
        };
        if len <= 1 {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; len];
        let readers = match ctx.list_readers(&mut buf) {
            Ok(it) => it,
            Err(PcscError::NoReadersAvailable) => return Ok(Vec::new()),
            Err(e) => {
                eprintln!("p11rand[iso7816]: SCardListReaders failed: {e:?}");
                return Err(Error::Transport);
            }
        };
        Ok(readers.map(|c: &CStr| c.to_string_lossy().into_owned()).collect())
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AppId {
    /// Card responds to GET CHALLENGE on its default selection.
    None,
    Piv,
    OpenPgp,
}

pub struct Source {
    card: Card,
    #[allow(dead_code)]
    app: AppId,
    /// Largest accepted GET CHALLENGE Le. Some cards cap below 255 (e.g. the
    /// 8-byte fixed-Le national-ID cards). We start optimistic at 128 (the
    /// largest power of two within short-Le) and halve on rejection so that
    /// fixed-Le cards land on 8 / 16 / 32 / 64 cleanly.
    max_chunk: usize,
}

const APP_PIV_AID: &[u8] = &[
    0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
];
const APP_OPENPGP_AID: &[u8] = &[0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];

fn sw_of(resp: &[u8]) -> u16 {
    if resp.len() < 2 {
        0
    } else {
        let n = resp.len();
        ((resp[n - 2] as u16) << 8) | (resp[n - 1] as u16)
    }
}

fn select_aid(card: &Card, aid: &[u8]) -> Result<bool, Error> {
    debug_assert!(aid.len() <= 32);
    let mut apdu = Vec::with_capacity(5 + aid.len());
    apdu.extend_from_slice(&[0x00, 0xA4, 0x04, 0x00, aid.len() as u8]);
    apdu.extend_from_slice(aid);

    let mut recv = [0u8; 258];
    let resp = card.transmit(&apdu, &mut recv).map_err(|e| {
        eprintln!("p11rand[iso7816]: SCardTransmit failed: {e:?}");
        Error::Transport
    })?;
    let sw = sw_of(resp);
    logd!("iso7816", "SELECT AID -> SW={:04X}", sw);
    Ok(sw == 0x9000 || (sw & 0xFF00) == 0x6100)
}

/// One GET CHALLENGE round of `n` bytes (1..=255). Returns `Ok(true)` if the
/// challenge was returned, `Ok(false)` if the card responded with SW != 9000
/// (caller will narrow `max_chunk` and retry), `Err` on transport failure.
fn try_get_challenge(card: &Card, n: usize, out: &mut [u8]) -> Result<bool, Error> {
    debug_assert!((1..=255).contains(&n) && out.len() >= n);
    let apdu = [0x00, 0x84, 0x00, 0x00, n as u8];
    let mut recv = [0u8; 258];
    let resp = card.transmit(&apdu, &mut recv).map_err(|e| {
        eprintln!("p11rand[iso7816]: SCardTransmit failed: {e:?}");
        Error::Transport
    })?;
    let sw = sw_of(resp);
    let body = if resp.len() >= 2 {
        &resp[..resp.len() - 2]
    } else {
        &[][..]
    };
    if sw != 0x9000 || body.len() != n {
        logd!("iso7816", "GET CHALLENGE({}) -> SW={:04X} len={}", n, sw, body.len());
        return Ok(false);
    }
    out[..n].copy_from_slice(body);
    Ok(true)
}

fn probe_app(card: &Card) -> Result<AppId, Error> {
    // Try GET CHALLENGE on the default selection first; identity / transport
    // / insurance cards typically support it directly without an applet
    // SELECT, and avoiding the SELECT keeps the card in its post-reset state.
    let mut throwaway = [0u8; 8];
    if try_get_challenge(card, throwaway.len(), &mut throwaway)? {
        return Ok(AppId::None);
    }

    for &(app, aid) in &[(AppId::Piv, APP_PIV_AID), (AppId::OpenPgp, APP_OPENPGP_AID)] {
        if !select_aid(card, aid)? {
            continue;
        }
        if try_get_challenge(card, throwaway.len(), &mut throwaway)? {
            return Ok(app);
        }
    }

    logd!("iso7816", "card does not support GET CHALLENGE on default/PIV/OpenPGP");
    Err(Error::Unsupported)
}

fn pcsc_no_card(e: &PcscError) -> bool {
    matches!(
        e,
        PcscError::NoSmartcard
            | PcscError::RemovedCard
            | PcscError::UnpoweredCard
            | PcscError::UnresponsiveCard
    )
}

pub fn open(reader: &str) -> Result<Source, Error> {
    let cname = CString::new(reader).map_err(|_| Error::Transport)?;
    let card = with_context(|ctx| {
        match ctx.connect(&cname, ShareMode::Shared, Protocols::T0 | Protocols::T1) {
            Ok(c) => Ok(c),
            Err(e) if pcsc_no_card(&e) => {
                logd!("iso7816", "SCardConnect({}): no card ({:?})", reader, e);
                Err(Error::NoCard)
            }
            Err(e) => {
                eprintln!("p11rand[iso7816]: SCardConnect({}) failed: {:?}", reader, e);
                Err(Error::Transport)
            }
        }
    })?;

    let app = match probe_app(&card) {
        Ok(a) => a,
        Err(Error::Unsupported) => {
            let _ = card.disconnect(Disposition::LeaveCard);
            return Err(Error::Unsupported);
        }
        Err(e) => {
            let _ = card.disconnect(Disposition::LeaveCard);
            return Err(e);
        }
    };

    Ok(Source { card, app, max_chunk: 128 })
}

impl Source {
    pub fn read(&mut self, mut buf: &mut [u8]) -> Result<(), Error> {
        // The card's accepted Le is unknown on the first call. Start at 128
        // (the largest power of two within short-Le) and halve on every SW
        // != 9000 until something works; the learned size is sticky. Some
        // cards require a *fixed* Le rather than a maximum (8-byte challenge
        // only, etc.); we always issue exactly `max_chunk` bytes per round
        // and discard any over-fetched tail when the caller asked for less.
        while !buf.is_empty() {
            if self.max_chunk == 0 {
                return Err(Error::Transport);
            }
            let chunk = self.max_chunk;
            let truncating = buf.len() < chunk;
            let mut scratch = [0u8; 256];
            let target: &mut [u8] = if truncating {
                &mut scratch[..chunk]
            } else {
                &mut buf[..chunk]
            };

            match try_get_challenge(&self.card, chunk, target)? {
                true => {
                    if truncating {
                        let take = buf.len();
                        buf[..take].copy_from_slice(&scratch[..take]);
                        buf = &mut [];
                    } else {
                        buf = &mut buf[chunk..];
                    }
                }
                false => {
                    // SW != 9000 — halve and retry. Down to 1 we give up.
                    if self.max_chunk > 1 {
                        self.max_chunk /= 2;
                        logd!(
                            "iso7816",
                            "card refused GET CHALLENGE({}); narrowing chunk to {}",
                            chunk,
                            self.max_chunk
                        );
                        continue;
                    }
                    return Err(Error::Transport);
                }
            }
        }
        Ok(())
    }
}

/// Power up the card just long enough to retrieve its ATR; format as
/// space-separated uppercase hex (e.g. `"3B 8F 01 80 5D 4E …"`). Independent
/// of [`open`] — cheap enough to call from the `list` helper for every reader.
pub fn read_atr(reader: &str) -> Result<String, Error> {
    let cname = CString::new(reader).map_err(|_| Error::Transport)?;
    let card = with_context(|ctx| {
        ctx.connect(&cname, ShareMode::Shared, Protocols::T0 | Protocols::T1)
            .map_err(|e| {
                if pcsc_no_card(&e) {
                    Error::NoCard
                } else {
                    Error::Transport
                }
            })
    })?;

    let mut name_buf = [0u8; 256];
    let mut atr_buf = [0u8; pcsc::MAX_ATR_SIZE];
    let status = card.status2(&mut name_buf, &mut atr_buf).map_err(|e| {
        eprintln!("p11rand[iso7816]: SCardStatus failed: {e:?}");
        Error::Transport
    })?;
    let atr = status.atr();
    let _ = card.disconnect(Disposition::LeaveCard);

    if atr.is_empty() {
        return Err(Error::Transport);
    }
    let mut out = String::with_capacity(atr.len() * 3);
    for (i, b) in atr.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        use std::fmt::Write;
        let _ = write!(&mut out, "{:02X}", b);
    }
    Ok(out)
}
