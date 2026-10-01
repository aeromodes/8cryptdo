<!-- SPDX-FileCopyrightText: 2026 AeroModes <mail@aeromod.es> -->
<!-- SPDX-License-Identifier: MIT -->

# 8CryptDo

Reverse-engineered documentation and tooling for the firmware encryption methods
used by 8BitDo for several products.

See `cryptdo8.py` for a decryption and re-encryption tool applying the
algorithms described in this document.

The tool potentially enables creating customized firmware. However, this
repository does not include any of the official firmware data. A script to
download the latest firmware files can be found at the
[fwupd/8bitdo-firmware](https://github.com/fwupd/8bitdo-firmware) repository,
with some older firmware binaries archived.

## Header

Looking at a firmware `.dat` file on the surface, a 28-byte plaintext header is
present.

```python
import struct

raw = open("sn30.dat", "rb").read()
version, addr, payload_len, pid = struct.unpack("<IIII", raw[:16])
# version     = 207        -> firmware == v2.07
# addr        = 0x08003400 -> destination (probably)
# payload_len = 99328      -> section payload length in bytes
# pid         = 0x0000     -> (optional, usually 0) USB PID
```

The rest of the header is zero. After seeking the payload length within the
file, another header and more firmware data may be present. We can refer to
these as firmware "sections." For now, we will only focus on the first section.

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
XOR out your guess to read the other. This recovers the keystream at that spot.

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
making roughly 18% of the firmware readable.

## Keystream rule

With a larger sample of the keystream, patterns became visible: positions 16
words apart that stepped by an almost constant amount, and bytes that moved by a
predictable size.

Through trial and error, it was discovered that every keystream word in a block
follows a formula:

```python
STEP  = 0x92A753FA
A_MUL = 0x80000301
ROT   = 18
UINT32_MAX = 0xFFFFFFFF

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

The entire 128-word block is determined by one 32-bit number: its "block key."
Within a block, walk a simple counter (`block_base(block) + pos * STEP`), and
XOR it with a mask that starts at the block key and rotates 18 bits every step.

Therefore, one known word unlocks a whole block. Rearranging the formula gives
the block key from any known keystream word:

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

The seed table itself appears to have no specific formula; it's probably 512
constant bytes stored somewhere in the bootloader of each device. However, the
XOR with `0xF9` provides a beautiful side effect: a *mirror law*. A block and
its partner `block ^ 0xF9` are built from the same two table entries swapped.

```python
mirror = block_key_of(block ^ 0xF9, seed_table)
assert mirror == rotr(block_key_of(block, seed_table), 16)
```

This cracked previously unknown regions. Instead of guessing a full block key
blind, you can guess two 16-bit halves and score which choice turns both blocks
into believable strings or ARM instructions.

With that, 100% coverage of all firmware data using this specific cipher was
obtained.

## Yichip cipher

The above cipher seems to be present on most GD32 devices from 8BitDo, so I've
dubbed it the "GD32 cipher."

There is a newer cipher used consistently by 8BitDo. Products using this cipher
include most of the Ultimate/Pro line, the M30, and the Zero 2, to name a few.
The latter two seem to have multiple sections in their firmware files: the first
being encoded with the older GD32 cipher, and the second with this new cipher.

After lots of experimentation, I discovered that this cipher isn't totally new.
It's actually a *variant* of the existing GD32 cipher with modified parameters:

```python
CHAIN_ROT = 18          # GD32: 3
STEP      = 0xEE97FAFA  # GD32: 0x92A753FA
A_MUL     = 0x01200210  # GD32: 0x80000301
ROT       = 16          # GD32: 18

def block_base(block):
    return (block * A_MUL + (block >> 8)) & UINT32_MAX
```

Notably, the block key is still built from an index and its `0xF9` partner, but
each is first turned into a seed table index by XOR-ing it with a value from a
small table. Here, `e` is the block's position in a 256-entry key schedule:

```python
INDEX_XOR = ((0x00, 0x82, 0x83, 0x81, 0x03, 0x81, 0x83, 0x81),
             (0x86, 0x83, 0x81, 0x82, 0x03, 0x05, 0x82, 0x82))

def seed_index(e):
    return e ^ INDEX_XOR[e >> 7][e & 7]

def block_key_of(block, seed_table):
    e = (block + (block >> 8)) & 0xFF
    hi = seed_table[seed_index(e)]
    lo = seed_table[seed_index(e ^ 0xF9)]
    return (hi << 16) | lo
```

The images decrypted appear to mostly be Yichip-based, judging by the SDK
remnants. In fact, a teardown of a recent Zero 2 device showed that it
specifically uses the YC3121. Therefore, I will dub this the "Yichip cipher."

Unlike the GD32 cipher, the Yichip cipher isn't limited to 256 blocks. Every 256
blocks, the schedule is wrapped: the counter base is increased by one (much like
the `block // 2` term of the GD32 cipher) and the key index advances by one.
This is shown in practice with early 64 BT builds, which span over 600 blocks
and decrypt end to end.

<!-- vim: set tw=80: -->
