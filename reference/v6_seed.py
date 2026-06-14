#!/usr/bin/env python3
"""snell-server v6.0.0b2 — VERIFIED PSK->profile shaping generator (bit-exact, Path B).

Reverse-engineered from the static binary and verified byte-exact against live gdb
captures for PSK A & B. Covers the per-listener "traffic-shaping profile" the server
derives once from the PSK at startup (seeder fn @0x41cc0).

Pipeline:
  master32 = blake2b(CONST24 || psk, 32)                 # libsodium generichash 0x1a50b8
  m0..m3   = little-endian u64 words of master32
  seed(idx,k64) = fmix64( (idx*MUL) ^ ((k64+ADD)&2^64)
                        ^ ((m1+GOLDEN) ^ ror(m2,47)) ^ (m0 ^ ror(m3,11)) )   # combiner 0x40eb8
  7 category seeds stored at struct offsets {0,72,96,136,168,192,216}.
  draw(cat,c)   = fold32( fmix64( (cat*GOLDEN) ^ K7 ^ ((c*K5+K4)&2^64)
                                ^ seed[CATMAP[cat]] ) )   # PRF 0x40fa0 via 0x41c98
  param(cat,c,lo,hi) = lo + draw(cat,c) % (hi-lo+1)       # bound 0x40e30 (reducer 0x40e08 = no-op)

Verified params include the FIRST-FRAME size field S+226 = param(18, 0x51a7, 17, 251):
  PSK A -> 251, PSK B -> 147  (== live struct). Measured wire F = field-1 due to the
  server holding at F-1 and closing (AEAD-open) at F.

NOT yet transcribed: the full ~30-entry param table (many drive the u16 padding
distribution tables TBL+104/+214 consumed by sampler 0x41ad0), the session cipher
(32B key -> AES-256-GCM vs ChaCha20-Poly1305), and the keystream wire framing.
"""
import hashlib

M = (1 << 64) - 1
C1 = 0xBF58476D1CE4E5B9
C2 = 0x94D049BB133111EB
GOLDEN = 0x9E3779B97F4A7C15
MUL = 0xD6E8FEB86659FD93
ADD = 0xA0761D6478BD642F
K7 = 0x8F3907F7B2B80C35
K5 = 0x589965CC75374CC3
K4 = 0x33A213EC50FFE2E9
CONST24 = bytes.fromhex("8d41a7135ce209bb702fd6943318c06e4a9125fdb80377ac")

# category-seed table: struct offset -> (idx, k64)  (from seeder fn 0x41cc0)
SEEDDEF = {
    0:   (16, 0xC9F4260B7D1E835A),
    72:  (0,  0x5D9217C083E64AB9),
    96:  (5,  0xB46C2E7D9A1538F1),
    136: (3,  0x3E8A91B52740F6CD),
    168: (21, 0x62D0B5E19C4A783F),
    192: (2,  0xA71F0C54D8396E2B),
    216: (28, 0x917B3C48E6A205D4),
}

# rodata 0x1b3390: category index -> routing byte -> seed offset
CATMAP = bytes([
    0x00, 0x00, 0x02, 0x04, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0xf8, 0x00, 0x00,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0xf8, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x00, 0x00, 0x08, 0x08, 0x08, 0x06, 0x06,
])
ROUTE = {0x00: 72, 0x02: 192, 0x04: 0, 0x06: 168, 0x08: 216, 0xF8: 96}


def fmix64(z):
    z &= M
    z ^= z >> 30
    z = (z * C1) & M
    z ^= z >> 27
    z = (z * C2) & M
    z ^= z >> 31
    return z


def ror(x, n):
    return ((x >> n) | (x << (64 - n))) & M


def master32(psk: bytes) -> bytes:
    return hashlib.blake2b(CONST24 + psk, digest_size=32).digest()


def seeds(psk: bytes) -> dict:
    mb = master32(psk)
    m = [int.from_bytes(mb[i:i + 8], "little") for i in (0, 8, 16, 24)]
    out = {}
    for off, (idx, k64) in SEEDDEF.items():
        t = ((idx * MUL) & M) ^ ((k64 + ADD) & M) \
            ^ (((m[1] + GOLDEN) & M) ^ ror(m[2], 47)) ^ (m[0] ^ ror(m[3], 11))
        out[off] = fmix64(t & M)
    return out


def draw(sd: dict, cat: int, c: int) -> int:
    seed = sd[ROUTE[CATMAP[cat]]]
    h = fmix64(((cat * GOLDEN) & M) ^ K7 ^ ((c * K5 + K4) & M) ^ seed)
    return (h ^ (h >> 32)) & 0xFFFFFFFF


def param(sd: dict, cat: int, c: int, lo: int, hi: int) -> int:
    return lo + (draw(sd, cat, c) % (hi - lo + 1)) if hi > lo else lo


def first_frame_size(psk: bytes) -> int:
    """The PSK-derived fixed first-frame size field (profile+226)."""
    return param(seeds(psk), 18, 0x51A7, 17, 251)


# ---------------------------------------------------------------------------
# Wire framing — the v6 first-frame salt-obfuscation (the entire v6 delta).
#
# Crypto (KDF=argon2id, AEAD=AES-128-GCM key=argon2[:16]) is UNCHANGED from v5.
# The only new thing in v6 is that each side's 16-byte session salt is not sent
# in the clear: it is SCATTERED across a PSK-sized first frame at PSK-derived
# permuted positions, each byte XORed with a PSK-derived keystream.
#
# Server decode (fn 0x42d68):  salt[i] = ks(i) ^ wire[perm[i]]      i=0..15
# Client/encode (fn 0x42fa8):  wire[perm[i]] = ks(i) ^ salt[i]      i=0..15
#   - the non-salt wire bytes are random filler (server reads only perm[0..15]).
#   - frame length  LEN = frame_len(psk)  (fn 0x42958 + decode site +16).
#   - keystream seed and perm seed are BOTH profile+136 (a category seed).
# ---------------------------------------------------------------------------
K7_S = 0x8F3907F7B2B80C35          # 0x42988 reuses K7
K8 = 0xE7037ED1A0B428DB
SHUF_SALT = 0xDAA66D2C7DDF743F     # extra constant in shuffle-PRF 0x42988
F_C = 0x51A7                       # keystream PRF 'b' arg (fn 0x41a98 -> 0x40fa0)


def frame_lo(psk: bytes) -> int:
    """profile+108 (LEN lower bound)."""
    return param(seeds(psk), 14, 0x7053, 16, 96)


HI_CAP = 128  # profile+208 is clamped to 0x80 at connection time (overwrites seeder value)


def frame_hi(psk: bytes) -> int:
    """profile+208 (LEN upper bound) = min(lo + (16 + draw(15)%145), 128)."""
    sd = seeds(psk)
    lo = param(sd, 14, 0x7053, 16, 96)
    return min(lo + param(sd, 15, 0x7053, 16, 160), HI_CAP)


def shuffle_rounds(psk: bytes) -> int:
    """profile+178 — number of Fisher-Yates passes (fn 0x42a10)."""
    return param(seeds(psk), 17, 0x51A7, 1, 4)


def frame_len(psk: bytes) -> int:
    """Total first-frame byte count = LEN_base + 16 (fn 0x42958 + decode site)."""
    sd = seeds(psk)
    lo, hi = frame_lo(psk), frame_hi(psk)
    return 16 + param(sd, 33, 0x7053, lo, hi)


def _fold32(z: int) -> int:
    return (z ^ (z >> 32)) & 0xFFFFFFFF


def _shuffle_prf(seed: int, ctr: int, idx: int) -> int:
    """fn 0x42988: fold32(fmix64((ctr*K8+K7) ^ seed ^ ((idx*K5+K4) ^ SHUF_SALT)))."""
    t = (((ctr * K8 + K7_S) & M) ^ seed ^ (((idx * K5 + K4) & M) ^ SHUF_SALT)) & M
    return _fold32(fmix64(t))


def perm(psk: bytes) -> list:
    """The PSK-derived index permutation over [0, LEN) (fn 0x42a10)."""
    seed = seeds(psk)[136]
    n = frame_len(psk)
    rounds = shuffle_rounds(psk)
    p = list(range(n))
    for r in range(rounds):
        ctr = (F_C + r) & 0xFFFF
        for i in range(n):
            j = i + (_shuffle_prf(seed, ctr, i) % (n - i))
            p[i], p[j] = p[j], p[i]
    return p


def keystream(psk: bytes, count: int = 16) -> bytes:
    """ks(i) = ((i*Ffield) ^ PRF(seed136, 2, 0x51a7, i)) & 0xff  (fn 0x41a98)."""
    seed = seeds(psk)[136]
    f = first_frame_size(psk)
    out = bytearray()
    for i in range(count):
        prf = fmix64(((2 * GOLDEN) & M) ^ ((F_C * K8 + K7_S) & M)
                     ^ ((i * K5 + K4) & M) ^ seed)
        out.append(((i * f) ^ _fold32(prf)) & 0xFF)
    return bytes(out)


def encode_first_frame(psk: bytes, salt: bytes, filler: bytes | None = None) -> bytes:
    """Build the LEN-byte first frame carrying `salt` (16B), as the client must."""
    assert len(salt) == 16
    n = frame_len(psk)
    p = perm(psk)
    ks = keystream(psk, 16)
    buf = bytearray(filler if filler is not None else bytes(n))
    assert len(buf) == n
    for i in range(16):
        buf[p[i]] = ks[i] ^ salt[i]
    return bytes(buf)


def decode_first_frame(psk: bytes, wire: bytes) -> bytes:
    """Recover the 16-byte salt from a LEN-byte first frame (server side)."""
    p = perm(psk)
    ks = keystream(psk, 16)
    return bytes(ks[i] ^ wire[p[i]] for i in range(16))


# ---------------------------------------------------------------------------
# Record layer — v6 wraps each v5-style AEAD chunk with a PSK-derived prefix.
#
# Validated end-to-end against the live server (e2e_build.py + capture18):
#   record(chunk) = [prefix bytes] + [v5 header CT] + [interleave] + [payload CT]
#   - prefix length = prefix_len(psk, chunk); content is the header AEAD's AAD.
#   - header CT = AES-128-GCM(key, nonce=2*chunk,   header_pt=[0x04,0,0,ilvBE,plenBE], aad=prefix)
#   - payload CT= AES-128-GCM(key, nonce=2*chunk+1, snell_req,                         aad=None)
#   - key = argon2id(psk, salt)[:16];  nonce = 12-byte LE counter (header even, payload odd).
# Bounds mirror the LEN bounds but with draw c=0; the prefix draw's PRF 'b' = chunk index.
# ---------------------------------------------------------------------------
def prefix_lo(psk: bytes) -> int:
    """profile+188 — prefix length lower bound."""
    return param(seeds(psk), 14, 0, 8, 80)


def prefix_hi(psk: bytes) -> int:
    """profile+90 — prefix length upper bound (same HI_CAP=128 as the LEN hi)."""
    sd = seeds(psk)
    return min(prefix_lo(psk) + param(sd, 15, 0, 16, 160), HI_CAP)


def _draw_b(sd: dict, cat: int, b: int, c: int) -> int:
    """draw with explicit PRF 'b' arg (fn 0x41030). draw(cat,c) == _draw_b(cat,0,c)."""
    seed = sd[ROUTE[CATMAP[cat]]]
    h = fmix64(((cat * GOLDEN) & M) ^ ((b * K8 + K7) & M) ^ ((c * K5 + K4) & M) ^ seed)
    return (h ^ (h >> 32)) & 0xFFFFFFFF


def prefix_len(psk: bytes, chunk: int = 0) -> int:
    """Per-chunk PSK-derived prefix byte count (fn 0x415c8). chunk index feeds PRF 'b'."""
    lo, hi = prefix_lo(psk), prefix_hi(psk)
    return lo + _draw_b(seeds(psk), 33, chunk, 0) % (hi - lo + 1)


if __name__ == "__main__":
    le = lambda h: int.from_bytes(bytes.fromhex(h), "little")
    seed_cases = [
        (b"test-psk-0123456789abcdef", 0,  "33ae989a1411adec"),
        (b"test-psk-0123456789abcdef", 72, "aeb5d932e976aaa3"),
        (b"test-psk-0123456789abcdef", 96, "20923ff18ac6656b"),
        (b"test-psk-fedcba9876543210", 72, "f0e8c06bd8e57309"),
        (b"test-psk-fedcba9876543210", 96, "2415d3e1bb494bd8"),
    ]
    frame_cases = [(b"test-psk-0123456789abcdef", 251), (b"test-psk-fedcba9876543210", 147)]
    ok = True
    for psk, off, want in seed_cases:
        got = seeds(psk)[off]
        good = got == le(want); ok &= good
        print(f"{psk.decode():26} seed+{off:<3} {got:016x} {'OK' if good else 'FAIL'}")
    for psk, want in frame_cases:
        got = first_frame_size(psk)
        good = got == want; ok &= good
        print(f"{psk.decode():26} S+226(frame) {got:>3}  {'OK' if good else 'FAIL'}")

    # Live profile fields captured via gdb (capture14) for both PSKs.
    A, B = b"test-psk-0123456789abcdef", b"test-psk-fedcba9876543210"
    field_cases = [
        ("seed@136", lambda p: seeds(p)[136],   {A: 0x3949AD7F58BE7803, B: 0x4BCFEE0036CD72D4}),
        ("rounds  ", shuffle_rounds,             {A: 4,  B: 3}),
        ("F field ", first_frame_size,           {A: 251, B: 147}),
        ("LEN lo  ", frame_lo,                    {A: 65, B: 31}),
        ("LEN hi  ", frame_hi,                    {A: 128, B: 82}),
    ]
    for name, fn, exp in field_cases:
        for psk in (A, B):
            got = fn(psk); good = got == exp[psk]; ok &= good
            v = f"{got:#018x}" if got > 0xFFFF else f"{got}"
            print(f"{psk.decode():26} {name} {v:>18}  {'OK' if good else 'FAIL ->'+str(exp[psk])}")
    len_exp = {A: 120, B: 57}  # authoritative LEN captured at decode site (capture16)
    for psk in (A, B):
        got = frame_len(psk); good = got == len_exp[psk]; ok &= good
        print(f"{psk.decode():26} LEN(frame) = {got}  {'OK' if good else 'FAIL ->'+str(len_exp[psk])}")

    # record prefix (capture19, PSK A chunk 0): lo=78 hi=128 len=107
    pref = (prefix_lo(A), prefix_hi(A), prefix_len(A, 0))
    good = pref == (78, 128, 107); ok &= good
    print(f"{A.decode():26} prefix lo/hi/len = {pref}  {'OK' if good else 'FAIL ->(78,128,107)'}")

    # Round-trip: encode a known salt then decode must recover it.
    import os
    for psk in (A, B):
        salt = os.urandom(16)
        wire = encode_first_frame(psk, salt, filler=bytes(range(frame_len(psk) % 256)) * 0 + bytes(frame_len(psk)))
        back = decode_first_frame(psk, wire)
        good = back == salt; ok &= good
        print(f"{psk.decode():26} roundtrip salt {'OK' if good else 'FAIL'}")
    print("ALL PASS" if ok else "FAIL")
