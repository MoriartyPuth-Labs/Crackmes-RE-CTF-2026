#!/usr/bin/env python3
"""
PoC / solver for the CTF 2026 "connected" reversing challenge.

Recovers the required user message purely from the validation constraints
(no answer is hard-coded), then derives the flag the way the binary does.

Challenge: crackmesone/ctf-2026-challenges-public -> connected/handout/connected
Flag format: CMO{...}

Usage:
    python solve.py
"""

# ---------------------------------------------------------------------------
# Constraints recovered from the binary / source (src/main.cpp):
#
#   target_pc validation (lines ~858-892):
#       len  == 8                       <- PC3 returns string length
#       hash == 100806214               <- PC4 combined checksum
#       is_even_printable               <- PC7: every byte even AND printable
#
#   PC4 combined hash (lines ~1063-1078):
#       adler      = adler_32(payload)
#       fletcher   = fletcher_16(payload)
#       shift_csum = sum(payload[i] << i)
#       palindrome = (payload reversed == payload)
#       combined   = ((adler ^ fletcher) * palindrome) ^ shift_csum
#
#   PC1 flag formatter (lines ~671-679):
#       chars   = "abcdefghijklmnopqrstuvwxyz0123456789_"   (len 37)
#       flag    = "CMO{secret_code_" + chars[(p[i]+i)%37] for each byte + "}"
#
#   The message the user types is "msg_" + payload (magic stripped by target).
# ---------------------------------------------------------------------------

TARGET_HASH = 100806214
TARGET_LEN  = 8
CHARS       = "abcdefghijklmnopqrstuvwxyz0123456789_"


def adler_32(data: bytes) -> int:
    a, b = 1, 0
    for x in data:
        a = (a + x) % 65521
        b = (a + b) % 65521
    return ((b << 16) + a) & 0xFFFFFFFF


def fletcher_16(data: bytes) -> int:
    a, b = 0, 0
    for x in data:
        a = (a + x) % 255
        b = (a + b) % 255
    return ((b << 8) | a) & 0xFFFF


def pc4_hash(p: bytes) -> int:
    adler = adler_32(p)
    fletcher = fletcher_16(p)
    shift_csum = 0
    for i in range(len(p)):
        shift_csum += p[i] << i
    is_pal = 1 if p == p[::-1] else 0
    return (((adler ^ fletcher) * is_pal) ^ shift_csum) & 0xFFFFFFFF


def make_flag(payload: bytes) -> str:
    body = "".join(CHARS[(payload[i] + i) % 37] for i in range(len(payload)))
    return "CMO{secret_code_" + body + "}"


def solve():
    # Even AND printable bytes: 0x20..0x7e with the low bit clear.
    even_printable = [c for c in range(0x20, 0x7F) if c % 2 == 0]

    # A length-8 palindrome is determined by its first 4 bytes.
    solutions = []
    for w in even_printable:
        for x in even_printable:
            for y in even_printable:
                for z in even_printable:
                    p = bytes([w, x, y, z, z, y, x, w])
                    if pc4_hash(p) == TARGET_HASH:
                        solutions.append(p)

    if not solutions:
        print("[-] No solution found")
        return

    for p in solutions:
        payload = p.decode("latin-1")
        print(f"[+] payload (message minus magic): {payload!r}")
        print(f"[+] what : msg_{payload}")
        print(f"[+] where: 100.25.26.10")
        print(f"[+] FLAG : {make_flag(p)}")


if __name__ == "__main__":
    solve()
