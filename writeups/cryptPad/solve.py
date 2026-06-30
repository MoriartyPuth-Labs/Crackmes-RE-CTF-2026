#!/usr/bin/env python3
"""
CryptPad solver.

The binary's "custom encryption" is pre_XOR(ks) -> RC4(key) -> post_XOR(ks)
with the SAME keystream ks both sides, so the XOR layers cancel and it reduces
to plain RC4. The 8-byte RC4 key is stored in the file's 13-byte trailer:
    [ uint32 N ][ 8-byte key ][ 0x08 ]
Recover the key from the trailer and RC4-decrypt the first N bytes.

Usage: python solve.py [flag.enc]
"""
import sys


def rc4(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    i = j = 0
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "flag.enc"
    ct = open(path, "rb").read()

    # Trailer: [uint32 N][8-byte key][0x08]
    assert ct[-1] == 0x08, "missing 0x08 trailer marker"
    N = int.from_bytes(ct[-13:-9], "little")
    key = ct[-9:-1]

    pt = rc4(key, ct[:N])
    flag = pt.split(b"\x00")[0].decode()

    print(f"N    = {N}")
    print(f"key  = {key.hex()}")
    print(f"flag = {flag}")


if __name__ == "__main__":
    main()
