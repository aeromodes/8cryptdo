<!-- SPDX-FileCopyrightText: 2026 AeroModes <mail@aeromod.es> -->
<!-- SPDX-License-Identifier: MIT -->

# 8CryptDo

Reverse-engineered documentation and tooling for the firmware encryption used by
8BitDo for several GD32-based products.

See `8cryptdo.py` for a decryption and re-encryption tool applying the algorithm
described in this document.

The tool potentially enables the possibility to create customized firmware.
However, this repository does not include any of the official firmware data. A
script to download the latest firmware files can be found at the
[fwupd/8bitdo-firmware](https://github.com/fwupd/8bitdo-firmware) repository,
with some older firmware binaries archived.

## Header

Looking at a firmware `.dat` file on the surface, a 28-byte plaintext header is
present.

```python
import struct

raw = open("sn30-v2_07.dat", "rb").read()
version, addr, payload_len = struct.unpack("<III", raw[:12])
# version     = 207        -> firmware == v2.07
# addr        = 0x08003400 -> destination (probably)
# payload_len = 99328      -> section payload length in bytes
```

With recent firmware files there is an unknown 32-bit value placed after these.
The rest of the header is zero.

## Keyless chaining layer

On certain firmware files, a pattern shows up: there is a layer that mixes each
word into the next.

```python
def rotr(x, r):
    return ((x >> r) | (x << (32 - r))) & 0xFFFFFFFF

dechained = [words[0]]
for i in range(1, len(words)):
    dechained.append(words[i] ^ rotr(words[i - 1], 3))
```

This chaining resets at every 128-word block boundary. The first word of a block
(`pos = 0`) has no predecessor term, and `pos = 1..127` chain from the word
before.

A keyless layer adds no security. Peeling it off reveals a cleaner intermediate
(`dechained`), where the only thing left hiding the plaintext is the keystream.

```python
P[i] = dechained[i] ^ keystream[i]
```

## Keystream factoring

The [fwupd/8bitdo-firmware](https://github.com/fwupd/8bitdo-firmware) repository
has a catalog of older firmware. These firmwares all seemed to have the chaining
layer.

XOR-ing some of them together after removing the chaining layer reveals long
runs of zeros and readable structure.

```python
plaintext_diff = [a ^ b for a, b in zip(dechained_a, dechained_b)]
```

If the same keystream is used in both...

```python
a = dechained_a[i] ^ dechained_b[i]
b = (P_a[i] ^ keystream[i]) ^ (P_b[i] ^ keystream[i])
c = P_a[i] ^ P_b[i]
assert a == b == c
```

the keystream cancels out.

This is a classic *many-time pad*. Such a keystream is only safe if used once.
For some reason, 8BitDo decided to use not just a per-product keystream, but a
single keystream across several products. This significantly weakened the
security of their cipher and made the rest of the analysis here possible.

## Reading the keystream

Once you know two plaintexts are XOR-ed together, you can guess part of one and
subtract your guess to read the other. This recovers the `keystream` at that
spot.

```python
keystream[i] = dechained[i] ^ P[i]
for fw in all_fw:
    P[fw][i] = dechained[fw][i] ^ keystream[i]
```

This would be easiest with strings, but the most productive trick here was the
cross-version relocation of ARM instructions. One function can appear in two
firmware versions at shifted positions. Where the keystream is known in one
version, you can line the shared code up in another and harvest new keystream
values.

Exploiting this took the known keystream words from ~1,500 to several thousand,
roughly 18% of the firmware readable.

## Keystream rule

With a larger sample of the `keystream`, patterns became visible. It had
positions 16 words apart that stepped by an almost constant amount, and each
byte moved by a predictable size.

Through trial and error, it was discovered that every keystream word in a block
follows a formula:

```python
STEP  = 0x92A753FA
A_MUL = 0x80000301
ROT   = 18
UINT32_MAX  = 0xFFFFFFFF

def rotr(x, r):
    r &= 31
    return ((x >> r) | (x << (32 - r))) & UINT32_MAX if r else x

def block_base(block):
    return (block * A_MUL + block // 2) & UINT32_MAX

def keystream(block, pos, block_key):
    counter = (block_base(block) + pos * STEP) & UINT32_MAX
    mask = rotr(block_key, ROT * pos)
    return counter ^ mask
```

Within a block, walk a simple counter (`block_base(block) + pos*STEP`), and XOR
it with a mask that starts at `block_key` and rotates 18 bits every step. The
entire 128-word block is determined by one 32-bit number, `block_key`.

One known word unlocks a whole block. Rearranging the formula gives the
`block_key` from any known keystream word:

```python
def block_key_from_known(block, pos, known_keystream):
    counter = (block_base(block) + pos * STEP) & UINT32_MAX
    return rotr(known_keystream ^ counter, -ROT * pos & 31)
```

## Seed table

Where did each block's key come from? It factors into two 16-bit halves pulled
from a 256-entry seed table:

```python
def block_key_of(block, seed_table):
    hi = seed_table[block]
    lo = seed_table[block ^ 0xF9]
    return (hi << 16) | lo
```

The seed table itself appears to have no specific formula, it's probably 512
constant bytes stored somewhere in the bootloader of each device. However, the
XOR with `0xF9` provides a beautiful side effect: a *mirror law*. A block and
its partner `block ^ 0xF9` are built from the same two table entries swapped.

```python
mirror = block_key_of(block ^ 0xF9, seed_table)
assert mirror == rotr(block_key_of(block, seed_table), 16)
```

This cracked previously unknown regions. Instead of guessing a full 32-bit
`block_key` blind, you can guess two 16-bit halves and score which choice turns
both blocks into believable strings or ARM instructions.

With that, 100% coverage of all firmware data using this specific cipher was
obtained.

## Remaining work

This cipher seems to cover most 8BitDo products circa 2020, and current products
that still use GD32 SoCs (including the SN30 Pro).

Some devices like the M30 and Zero 2 appear to be multi-section, with some
firmware data using this cipher and another firmware with a different encryption
scheme.

Newer devices, at least those with a different SoC, seem to have a stronger
firmware encryption scheme. Some naïve analysis shows it may potentially be
shared, but unsure. Need to investigate that further.

<!-- vim: set tw=80: -->
