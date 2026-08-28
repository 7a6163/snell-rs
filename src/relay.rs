//! Adaptive chunk sizing for the target→client relay direction.
//!
//! Starts at 1 KB and doubles toward 16 KB on consecutive full reads.
//! Backs off on partial reads (indicates network pressure or EOF approach).

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::cipher::SnellCipher;
use crate::snell::write_chunk_sized;

const SIZER_MIN: usize = 1_024; // 1 KB
const SIZER_MAX: usize = 16_384; // 16 KB
const RAMP_AFTER: u32 = 2; // consecutive full reads before doubling

pub struct AdaptiveSizer {
    current: usize,
    consecutive_full: u32,
}

impl AdaptiveSizer {
    pub fn new() -> Self {
        Self {
            current: SIZER_MIN,
            consecutive_full: 0,
        }
    }

    pub fn next_size(&self) -> usize {
        self.current
    }

    /// Call when a read exactly filled the requested size → consider ramping.
    pub fn on_full(&mut self) {
        self.consecutive_full += 1;
        if self.consecutive_full >= RAMP_AFTER {
            self.consecutive_full = 0;
            self.current = (self.current * 2).min(SIZER_MAX);
        }
    }

    /// Call when a read returned fewer bytes than requested → back off.
    pub fn on_partial(&mut self) {
        self.consecutive_full = 0;
        self.current = (self.current / 2).max(SIZER_MIN);
    }
}

impl Default for AdaptiveSizer {
    fn default() -> Self {
        Self::new()
    }
}

/// Relay bytes from `reader` (target) to `writer` (client) using adaptive chunk sizing.
/// Sends a zero-chunk after target closes, then returns writer and cipher for reuse.
pub async fn copy_t2c_adaptive<R, W>(
    mut reader: R,
    mut writer: W,
    mut cipher: SnellCipher,
) -> Result<(W, SnellCipher)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut sizer = AdaptiveSizer::new();
    let mut buf = vec![0u8; SIZER_MAX];

    loop {
        let cap = sizer.next_size();
        let n = reader.read(&mut buf[..cap]).await?;
        if n == 0 {
            break;
        }
        if n >= cap {
            sizer.on_full();
        } else {
            sizer.on_partial();
        }
        write_chunk_sized(&mut writer, &mut cipher, &buf[..n], cap).await?;
    }
    writer.write_all(&cipher.seal_zero()?).await?;
    Ok((writer, cipher))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::SALT_LEN;

    #[test]
    fn sizer_ramps_after_two_full_reads() {
        let mut s = AdaptiveSizer::new();
        assert_eq!(s.next_size(), 1024);
        s.on_full();
        assert_eq!(s.next_size(), 1024); // not yet
        s.on_full();
        assert_eq!(s.next_size(), 2048); // doubled
        for _ in 0..10 {
            s.on_full();
            s.on_full();
        }
        assert_eq!(s.next_size(), 16384); // capped
    }

    #[test]
    fn sizer_backs_off_on_partial() {
        let mut s = AdaptiveSizer::new();
        // Ramp to 4096 before backing off. Halving 2048 lands exactly on
        // SIZER_MIN, so starting there cannot tell "halve" apart from "return
        // the floor" -- the step from 4096 to 2048 is what pins the halving.
        for _ in 0..4 {
            s.on_full();
        }
        assert_eq!(s.next_size(), 4096);
        s.on_partial();
        assert_eq!(s.next_size(), 2048, "must halve, not drop to the floor");
        s.on_partial();
        assert_eq!(s.next_size(), 1024);
        s.on_partial();
        assert_eq!(s.next_size(), 1024, "floor at SIZER_MIN");
    }

    /// The sizer's unit tests drive it directly; this pins the wiring between a
    /// read's length and the ramp decision, which nothing else covered. The
    /// relay is only otherwise exercised end-to-end, where a wrong sizing
    /// decision still moves every byte and so goes unnoticed -- the chunk sizes
    /// are the whole point of the module.
    #[tokio::test]
    async fn relay_ramps_chunk_size_on_sustained_full_reads() {
        const PSK: &[u8] = b"relay-test-psk-0123456789abcd";
        let salt = [3u8; SALT_LEN];
        let src = vec![0xABu8; 120_000];

        let mut wire = Vec::new();
        copy_t2c_adaptive(&src[..], &mut wire, SnellCipher::new(PSK, &salt).unwrap())
            .await
            .unwrap();

        let mut rx = SnellCipher::new(PSK, &salt).unwrap();
        let mut r = &wire[..];
        let mut sizes = Vec::new();
        while let Some(d) = crate::snell::read_chunk(&mut r, &mut rx).await.unwrap() {
            sizes.push(d.len());
        }

        assert_eq!(sizes.iter().sum::<usize>(), src.len(), "every byte relayed");
        assert_eq!(sizes[0], SIZER_MIN, "first read uses the floor");
        // Not SIZER_MAX: the ramp tops out at 16384 but a chunk carries at most
        // 0x3fff bytes, so `write_chunk_sized` splits each full read at the
        // protocol ceiling and emits a 1-byte chunk after it.
        assert_eq!(
            *sizes.iter().max().unwrap(),
            0x3fff,
            "sustained full reads must ramp to the protocol chunk ceiling"
        );
        assert!(
            sizes.iter().filter(|&&n| n == 1).count() > 0,
            "SIZER_MAX exceeding the 0x3fff chunk ceiling leaves a 1-byte tail \
             chunk per full read; if that stops happening the ceilings were \
             reconciled and this test should be updated"
        );
    }

    #[test]
    fn sizer_resets_streak_on_partial() {
        let mut s = AdaptiveSizer::new();
        s.on_full(); // 1 streak
        s.on_partial(); // reset streak
        s.on_full(); // streak = 1 again — NOT doubled yet
        assert_eq!(s.next_size(), 1024);
    }
}
