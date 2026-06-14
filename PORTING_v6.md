# Porting snell v6.0.0b2 into snell-rs

Self-contained spec to implement **snell v6.0.0b2** interop. No binary or reverse
engineering needed — every formula below is verified, and `tests/v6_test_vectors.json`
+ `reference/v6_seed.py` are the golden oracle (both validated **end-to-end against the
live official server**: it decoded our crafted frame and `connect()`-ed to our target).

> **Golden rule:** if the Rust output matches `tests/v6_test_vectors.json` byte-for-byte
> at every layer, it interops with the real Surge v6 server. Build with TDD against it.

## What v6 changes vs v5 (the whole delta)

The crypto layer is **identical to v5** — reuse it as-is:
- KDF: argon2id(psk, salt, t=3, m=8 KiB, p=1, v=0x13, 32B), key = `out[:16]`.
- Cipher: AES-128-GCM, 12-byte LE counter nonce. → existing `src/cipher.rs::SnellCipher`.
- Chunk inner structure, interleave, snell request format → existing `src/snell.rs`.

v6 adds **two PSK-derived obfuscation layers**:
1. **Handshake first frame** — the 16-byte salt is no longer sent raw. It is scattered
   into a PSK-sized frame at permuted positions, each XOR a keystream byte.
2. **Per-chunk prefix** — every AEAD chunk is preceded by `prefix_len` PSK-derived bytes,
   and **those bytes are the chunk header's AEAD AAD** (v5 uses empty AAD).

Everything is derived once-per-connection from the PSK (deterministic), via a "profile".

## Constants (see `constants` in the vectors JSON)

```
M       = 2^64-1     GOLDEN = 0x9E3779B97F4A7C15
C1 = 0xBF58476D1CE4E5B9   C2 = 0x94D049BB133111EB     # splitmix64 fmix
K7 = 0x8F3907F7B2B80C35   K8 = 0xE7037ED1A0B428DB
K5 = 0x589965CC75374CC3   K4 = 0x33A213EC50FFE2E9
SHUF_SALT = 0xDAA66D2C7DDF743F     HI_CAP = 128
CONST24   = 8d41a7135ce209bb702fd6943318c06e4a9125fdb80377ac
CATMAP(40)= use the exact `CATMAP` hex from the JSON (40 bytes)
ROUTE: 0x00->72  0x02->192  0x04->0  0x06->168  0x08->216  0xF8->96
```

All arithmetic is `u64` **wrapping** (use `wrapping_mul`/`wrapping_add`).
`fmix64(z): z^=z>>30; z*=C1; z^=z>>27; z*=C2; z^=z>>31`.  `fold32(z)=(z^(z>>32)) as u32`.

## Profile derivation (per connection, from PSK)

```
master32 = blake2b-256(CONST24 || psk)            # 32-byte BLAKE2b, no key
m0..m3   = little-endian u64 words of master32
# 7 category seeds at profile offsets {0,72,96,136,168,192,216}; each from (idx,k64):
#   0:(16,0xC9F4260B7D1E835A) 72:(0,0x5D9217C083E64AB9) 96:(5,0xB46C2E7D9A1538F1)
#   136:(3,0x3E8A91B52740F6CD) 168:(21,0x62D0B5E19C4A783F) 192:(2,0xA71F0C54D8396E2B)
#   216:(28,0x917B3C48E6A205D4)
seed(idx,k64) = fmix64( (idx*MUL) ^ ((k64+ADD) mod 2^64) ^ ((m1+GOLDEN) ^ ror(m2,47)) ^ (m0 ^ ror(m3,11)) )
  MUL=0xD6E8FEB86659FD93   ADD=0xA0761D6478BD642F   ror = rotate-right
```

```
state_loader(cat) = seed[ ROUTE[CATMAP[cat]] ]   (cat>39 -> seed[96])
draw_b(cat,b,c)   = fold32(fmix64( (cat*GOLDEN) ^ (b*K8+K7) ^ (c*K5+K4) ^ state_loader(cat) ))
draw(cat,c)       = draw_b(cat,0,c)
param(cat,c,lo,hi)= lo + draw(cat,c) % (hi-lo+1)
```

Verify `seeds` and `seed136` against the JSON first — they gate everything else.

## Handshake first frame

```
F      = param(18,0x51A7,17,251)                       # F_field
rounds = param(17,0x51A7,1,4)                          # shuffle_rounds
lo     = param(14,0x7053,16,96)                        # frame_lo
hi     = min(lo + param(15,0x7053,16,160), HI_CAP)     # frame_hi  (clamp to 128!)
LEN    = 16 + (lo + draw(33,0x7053) % (hi-lo+1))       # frame_len  total frame bytes
seed136= seed at offset 136                            # keystream & perm seed

# keystream (16 bytes)
ks(i) = ( (i*F) XOR fold32(fmix64( (2*GOLDEN) ^ (0x51A7*K8+K7) ^ (i*K5+K4) ^ seed136 )) ) & 0xFF

# permutation over [0,LEN): identity, then `rounds` Fisher-Yates passes
for r in 0..rounds:  ctr=0x51A7+r
  for i in 0..LEN:   j = i + shuf(seed136,ctr,i) % (LEN-i); swap(perm[i],perm[j])
shuf(seed,ctr,idx) = fold32(fmix64( (ctr*K8+K7) ^ seed ^ ((idx*K5+K4) ^ SHUF_SALT) ))

# encode: pick random 16-byte salt + (LEN-16) random filler; place salt scattered:
frame = LEN bytes (filler);  for i in 0..16:  frame[perm[i]] = ks(i) ^ salt[i]
# decode (server side / for tests): salt[i] = ks(i) ^ frame[perm[i]]
```

The client sends exactly `frame` (LEN bytes) first, then derives `key = argon2id(psk,salt)[:16]`.
Vectors use a fixed salt + **zero filler** so `first_frame_hex` is deterministic — match it exactly.

## Per-chunk prefix (the record layer)

```
prefix_lo = param(14,0,8,80)
prefix_hi = min(prefix_lo + param(15,0,16,160), HI_CAP)        # clamp to 128
prefix_len(k) = prefix_lo + draw_b(33, b=k, c=0) % (prefix_hi-prefix_lo+1)   # k = chunk index
```

Each chunk on the wire (both directions):
```
[prefix: prefix_len(k) bytes]  [header CT: 23B]  [interleave]  [payload CT: plen+16]
  header CT  = AES-128-GCM(key, nonce=2k,   PT=[0x04,0,0,ilv_hi,ilv_lo,plen_hi,plen_lo], AAD=prefix)
  payload CT = AES-128-GCM(key, nonce=2k+1, PT=snell_request,                            AAD=none)
```
- `k` is the chunk index for that direction, starting 0. Nonce = 12-byte LE = 2k (header), 2k+1 (payload).
- **Prefix content is the header's AAD.** Client picks random prefix bytes and feeds the *same*
  bytes as AAD when sealing the header. Server reads `prefix_len` bytes, uses them as AAD to open.
- snell request payload = `[0x01][cmd][cid_len][host_len][host][port BE]` (= v5; `CMD_CONNECT=0x01`).

### The one change to existing v5 cipher code
`src/cipher.rs` currently seals/opens the header with empty AAD (`&[]`). For v6, thread the
`prefix` bytes through as the header AAD (payload AAD stays empty). Keep v5 behavior selectable
(e.g. a protocol-version flag or a `v6` variant) so v5 still works.

## Suggested module layout

```
src/v6/mod.rs        # pub use; Profile struct cached per connection
src/v6/profile.rs    # blake2b master, seeds, state_loader, draw/draw_b, param  (+ unit tests vs JSON seeds)
src/v6/frame.rs      # F, rounds, lo/hi, frame_len, keystream, perm, encode/decode_first_frame
src/v6/record.rs     # prefix_lo/hi, prefix_len(k); chunk read/write with prefix + header-AAD
```
Reuse `cipher.rs` (AES-GCM/nonce) and `snell.rs` (parse_request, interleave, command consts).

## Test plan (TDD against `tests/v6_test_vectors.json`)

Load the JSON; for each vector assert, in this order (each gates the next):
1. `seeds` / `seed136`  (profile correct)
2. `F_field`, `shuffle_rounds`, `frame_lo`, `frame_hi`, `frame_len`
3. `keystream_hex`, `perm`
4. `encode_first_frame(psk, salt, zero_filler)` == `first_frame_hex`; and decode round-trips `salt_hex`
5. `prefix_lo/hi`, `prefix_len_chunk0`
6. `argon2_key_hex` == argon2id(psk, salt)[:16]
7. Build first record from `salt_hex`+target with **zero prefix**; `first_record_hex` and
   `full_blob_hex` must match. (`full_blob_hex` is exactly what the live server accepted.)

Cross-check anytime by running `python3 reference/v6_seed.py` (prints `ALL PASS`).

## Remaining (not interop-blocking; defer)
- Multi-chunk prefix for k>0 (formula `prefix_len(psk,k)` already general — add a multi-chunk vector).
- Server→client direction is symmetric (server generates its own salt via random + same encode).
- Traffic-shaping padding distribution (anti-DPI), not required for a working tunnel.
- Bump `Cargo.toml` version + advertise v6 once the above tunnels end-to-end.
