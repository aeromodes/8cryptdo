#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 AeroModes <mail@aeromod.es>
# SPDX-License-Identifier: MIT
"""8CryptDo v1.1: 8BitDo firmware encryption tool

Usage:
 - 8cryptdo.py decrypt in.dat [-s N] [-c gd32|yichip] -o out.bin
 - 8cryptdo.py encrypt template.dat payload.bin [-s N] [-c gd32|yichip]
   -o new.dat

GitHub: https://github.com/aeromodes/8cryptdo
"""

import sys
import struct
import argparse
import math

UINT32_MAX = 0xFFFFFFFF

BLOCK = 128

SEED_TABLE = (
    0xF428, 0x50C3, 0x3071, 0x722A, 0x848D, 0x0DD7, 0x5B3E, 0x56EF, 0x3AD3,
    0x510A, 0x0147, 0x417A, 0x886C, 0x12AE, 0x3C9C, 0x5DD3, 0x2D6E, 0x615B,
    0xD68B, 0x5BCC, 0xD3E3, 0x2D48, 0xC15B, 0xA342, 0x5E54, 0x4D90, 0xAF30,
    0x7A74, 0x05A8, 0x5E0B, 0x53B4, 0xC56A, 0xDB56, 0x6F88, 0x367E, 0x3814,
    0x4E53, 0x184E, 0x2227, 0x0024, 0x7705, 0x4FD0, 0x42AE, 0x71C5, 0x5004,
    0xBFF0, 0x1E71, 0x3330, 0xF02A, 0x470B, 0x4142, 0x2EA0, 0x56EC, 0x424F,
    0x7982, 0x1361, 0xD7C3, 0x0DC8, 0x1552, 0x5537, 0xA2B9, 0x4E96, 0x7243,
    0xA00A, 0xC620, 0xED93, 0xE24F, 0x82DC, 0x0BE4, 0x240B, 0x7118, 0xDD34,
    0xF0D2, 0xE406, 0x7F07, 0xF800, 0x327B, 0xDB9C, 0x547A, 0xFCC2, 0x8835,
    0x539A, 0x320D, 0xF492, 0xE6EC, 0x26BC, 0x6FC3, 0xA9C8, 0x00E9, 0xC11B,
    0xD224, 0x199A, 0x2484, 0x1F47, 0xCE36, 0x2F14, 0x9972, 0x6801, 0x6C86,
    0x5C33, 0x8274, 0x0E1F, 0xF5F6, 0x885F, 0x02B3, 0x9605, 0x39BC, 0xDBBD,
    0x9E2D, 0xED7D, 0x5968, 0xE436, 0xA8DD, 0x1981, 0x5B9A, 0x93F4, 0x91D5,
    0x4CBE, 0x5CFC, 0x8FC3, 0x1484, 0x101C, 0x4251, 0x17BF, 0xFB91, 0xF156,
    0x0B4A, 0x2205, 0x949F, 0x1E4E, 0xC9F0, 0xB66C, 0xACCF, 0x5C44, 0xE3BB,
    0x5BFD, 0xF3EC, 0xA47C, 0x6BC8, 0x46B3, 0xB5CD, 0xD223, 0x7022, 0x046F,
    0xB7C8, 0x0B51, 0xD416, 0x5041, 0x95D1, 0xB7F0, 0x456F, 0xEC16, 0xE119,
    0x8BD4, 0x43AD, 0xC04F, 0x16B2, 0x802D, 0xD7E2, 0x16AC, 0x833F, 0x1660,
    0x993E, 0xD4F4, 0x9AC7, 0xE9A1, 0x12A5, 0x0504, 0x931E, 0xECC2, 0x157D,
    0xE013, 0x8562, 0x8693, 0x9237, 0xD7F7, 0xC59D, 0xEAC2, 0x7CD0, 0xBA88,
    0x5BD1, 0x09B5, 0x9C15, 0xACC0, 0xAA02, 0x0FDE, 0x434D, 0xE9E5, 0x8BE7,
    0x601E, 0x8B55, 0x2E39, 0x1C1D, 0x0CDC, 0x1E81, 0xE405, 0x82AF, 0xF6C2,
    0x53E9, 0x3E0A, 0x09DD, 0x173E, 0xA207, 0xD23D, 0x5DDF, 0x182E, 0x1A62,
    0xC02E, 0xEDB9, 0x0D6A, 0x6687, 0x37B4, 0x1EDC, 0xEACD, 0xC515, 0x495B,
    0x39B2, 0x9972, 0x9E49, 0xAC4E, 0xD364, 0x96B7, 0xBBB5, 0x412E, 0x8BB7,
    0xA647, 0x3A9C, 0x93CF, 0x0AD3, 0x388C, 0x9C1C, 0x8268, 0x0BCD, 0xC814,
    0x6521, 0x608A, 0x7120, 0xDBCA, 0xD2D0, 0xFA37, 0xC9A5, 0x56C8, 0x2066,
    0xF8C9, 0x1872, 0x352B, 0x1908, 0x991E, 0xA478, 0x45A3, 0x0E8C, 0x2486,
    0xE293, 0x8D55, 0x2912, 0x2129
)


def rotr(x, r):
    r &= 31
    x &= UINT32_MAX
    return ((x >> r) | (x << (32 - r))) & UINT32_MAX if r else x


class Cipher:
    """Keystream XOR on 32-bit words, with chaining that resets every
    BLOCK words.
    """
    NAME = ""
    STEP = 0
    CHAIN_ROT = 0
    MASK_ROT = 0
    MIRROR_XOR = 0xF9
    MAX_BLOCKS = 0

    def block_base(self, block):
        """Per-block starting value of the keystream counter."""
        raise NotImplementedError

    def block_key(self, block):
        """Build a block's 32-bit key from two 16-bit seed table entries."""
        raise NotImplementedError

    def keystream(self, block, pos):
        """Sequence of pseudorandom values to XOR against."""
        counter = (self.block_base(block) + pos * self.STEP) & UINT32_MAX
        mask = rotr(self.block_key(block), self.MASK_ROT * pos)
        return counter ^ mask


class GD32(Cipher):
    NAME = "gd32"
    STEP = 0x92A753FA
    CHAIN_ROT = 3
    MASK_ROT = 18
    A_MUL = 0x80000301
    MAX_BLOCKS = len(SEED_TABLE)

    def block_base(self, block):
        return (block * self.A_MUL + block // 2) & UINT32_MAX

    def block_key(self, block):
        return (SEED_TABLE[block] << 16) | SEED_TABLE[block ^ self.MIRROR_XOR]


class Yichip(Cipher):
    NAME = "yichip"
    STEP = 0xEE97FAFA
    CHAIN_ROT = 18
    MASK_ROT = 16
    A_MUL = 0x01200210
    INDEX_XOR = ((0x00, 0x82, 0x83, 0x81, 0x03, 0x81, 0x83, 0x81),
                 (0x86, 0x83, 0x81, 0x82, 0x03, 0x05, 0x82, 0x82))
    MAX_BLOCKS = math.inf

    def block_base(self, block):
        return (block * self.A_MUL + (block >> 8)) & UINT32_MAX

    def seed_index(self, e):
        return e ^ self.INDEX_XOR[e >> 7][e & 7]

    def block_key(self, block):
        e = (block + (block >> 8)) & 0xFF
        return (SEED_TABLE[self.seed_index(e)] << 16) | \
            SEED_TABLE[self.seed_index(e ^ self.MIRROR_XOR)]


CIPHERS = {c.NAME: c for c in (GD32(), Yichip())}


def decrypt_word(C, i, cipher):
    """Undo per-block chaining, then cancel keystream."""
    block, pos = i // BLOCK, i % BLOCK
    dechained = C[i] if pos == 0 else C[i] ^ rotr(C[i - 1], cipher.CHAIN_ROT)
    return dechained ^ cipher.keystream(block, pos)


def encrypt_word(P, C, i, cipher):
    """Apply keystream, then re-chain per block."""
    block, pos = i // BLOCK, i % BLOCK
    dechained = P[i] ^ cipher.keystream(block, pos)
    return dechained if pos == 0 else \
        dechained ^ rotr(C[i - 1], cipher.CHAIN_ROT)


def decrypt_payload(C, cipher):
    return [decrypt_word(C, i, cipher) for i in range(len(C))]


def encrypt_payload(P, C_template, cipher):
    if len(P) != len(C_template):
        raise ValueError(
            f"Payload length must match template ({len(C_template)} words)")
    C = list(C_template)
    for i in range(len(P)):
        C[i] = encrypt_word(P, C, i, cipher)
    return C


def parse_sections(raw):
    """Return list of data from concatenated 28-byte-header sections."""
    secs = []
    off = 0
    while off + 28 <= len(raw):
        version, addr, payload_len, pid = struct.unpack(
            "<IIII", raw[off:off + 16])
        if payload_len <= 0 or off + 28 + payload_len > len(raw):
            break
        secs.append(dict(offset=off, id=version, addr=addr,
                         payload_len=payload_len, pid=pid))
        off += 28 + payload_len
    return secs


def select_section(raw, index):
    secs = parse_sections(raw)
    if not secs:
        raise SystemExit("No valid section header found")
    if not 0 <= index < len(secs):
        raise SystemExit(
            f"Section {index} not found ({len(secs)} section(s))")
    return secs, secs[index]


def words(payload):
    n = len(payload) // 4
    return list(struct.unpack(f"<{n}I", payload[:n * 4])), payload[n * 4:]


def cmd_decrypt(args):
    """Decrypt one section of a firmware to a standalone binary."""
    raw = args.infile.read()
    secs, sec = select_section(raw, args.section)
    cipher = CIPHERS[args.cipher]
    C, tail = words(
        raw[sec["offset"] + 28:sec["offset"] + 28 + sec["payload_len"]])
    n = len(C)
    decrypt_max = cipher.MAX_BLOCKS * BLOCK
    if n > decrypt_max:
        sys.stderr.write(f"Warning: section {args.section} is {n} words but "
                         f"only {decrypt_max} are decryptable\n")
        n = decrypt_max
    P = decrypt_payload(C[:n], cipher)
    data = struct.pack(f"<{n}I", *P)
    if n == len(C):
        data += tail
    args.output.write(data)
    sys.stderr.write(f"Section {args.section}/{len(secs) - 1}: id={sec['id']} "
                     f"addr=0x{sec['addr']:08x} pid=0x{sec['pid']:04x} "
                     f"payload_len={len(C) * 4}\n")
    sys.stderr.write(f"Wrote {n} words ({len(data)} bytes) using "
                     f"{args.cipher}\n")


def cmd_encrypt(args):
    """Encrypt binary onto one section of a template firmware."""
    template_raw = args.template.read()
    _, sec = select_section(template_raw, args.section)
    cipher = CIPHERS[args.cipher]
    base = sec["offset"] + 28
    C_template, _ = words(template_raw[base:base + sec["payload_len"]])
    raw_in = args.infile.read()
    raw_in += b"\x00" * (-len(raw_in) % 4)
    P, _ = words(raw_in)
    if len(P) > len(C_template):
        raise SystemExit(f"Payload ({len(P)} words) is longer than section "
                         f"{args.section} ({len(C_template)} words)")
    if len(P) > cipher.MAX_BLOCKS * BLOCK:
        raise SystemExit(f"Payload ({len(P)} words) is longer than "
                         f"{args.cipher} can encrypt "
                         f"({cipher.MAX_BLOCKS * BLOCK} words)")
    pad = min(-len(P) % BLOCK, len(C_template) - len(P))
    P = P + [0] * pad
    C = encrypt_payload(P, C_template[:len(P)], cipher)
    graft = template_raw[base + 4 * len(P):]
    out = template_raw[:base] + struct.pack(f"<{len(C)}I", *C) + graft
    args.output.write(out)
    if pad:
        sys.stderr.write(
            f"Padded {pad} zero word(s) to reach block boundary\n")
    sys.stderr.write(f"Re-encrypted {len(C)} words using {args.cipher}, "
                     f"{len(graft)} bytes left from template\n")


def main():
    ap = argparse.ArgumentParser(
        description="8CryptDo v1.1: 8BitDo firmware encryption tool",
        epilog="GitHub: https://github.com/aeromodes/8cryptdo")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("decrypt", help=cmd_decrypt.__doc__,
                       description=cmd_decrypt.__doc__)
    d.add_argument("infile", type=argparse.FileType(
        "rb"), help="Input .dat (- for stdin)")
    d.add_argument("-s", "--section", type=int, default=0,
                   help="Section index (default: 0)")
    d.add_argument("-c", "--cipher", choices=CIPHERS, default="gd32",
                   help="Cipher (default: gd32)")
    d.add_argument("-o", "--output", type=argparse.FileType("wb"),
                   default=sys.stdout.buffer,
                   help="Output file (default: stdout)")
    d.set_defaults(func=cmd_decrypt)
    e = sub.add_parser("encrypt", help=cmd_encrypt.__doc__,
                       description=cmd_encrypt.__doc__)
    e.add_argument("template", type=argparse.FileType("rb"),
                   help="Original firmware .dat to graft onto")
    e.add_argument("infile", type=argparse.FileType("rb"),
                   help="Payload to re-encrypt (- for stdin)")
    e.add_argument("-s", "--section", type=int, default=0,
                   help="Section index (default: 0)")
    e.add_argument("-c", "--cipher", choices=CIPHERS, default="gd32",
                   help="Cipher (default: gd32)")
    e.add_argument("-o", "--output", type=argparse.FileType("wb"),
                   default=sys.stdout.buffer,
                   help="Output file (default: stdout)")
    e.set_defaults(func=cmd_encrypt)
    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

# vim: set textwidth=79:
