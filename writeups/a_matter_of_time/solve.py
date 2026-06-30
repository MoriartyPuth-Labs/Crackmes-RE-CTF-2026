#!/usr/bin/env python3
"""
a_matter_of_time.exe  -  Crackmes.one Reverse Engineering CTF 2026  (@heapsoverflow)
Offline solver / PoC.

The flag is AES-CBC-128:
    key = "nicetryboogeyman"            (the author's username, leaked in the PDB path)
    IV  = 16 ASCII digits, an "amalgamated value from UNIX decimal timestamps"
    ct  = 48 bytes recovered from the binary / live process memory

Key insight: in CBC, plaintext blocks >= 1 depend only on the key (not the IV),
so most of the flag falls out with the key alone. Only block 0 needs the IV.

Requires: pip install pycryptodome
"""
from Crypto.Cipher import AES

# ---------------------------------------------------------------------------
# Recovered ciphertext (48 bytes = 3 AES blocks).
# Pulled from the running process's memory as a 97-char hex string; the real
# value is the 96 hex chars after dropping the stray leading nibble (verified
# by the clean PKCS#7 padding it decrypts to).
# ---------------------------------------------------------------------------
CT_HEX = "4c4635258cf6eca5d80b8e050a9e5b04f1a9c979bc55f3f4773971ed2f81a96967bb3569fa002f549cc970a18779b3a7"
CT  = bytes.fromhex(CT_HEX)
KEY = b"nicetryboogeyman"             # 16 bytes -> AES-128

assert len(CT) == 48 and len(KEY) == 16

# ---------------------------------------------------------------------------
# Step 1 - decrypt blocks 1 & 2 with the KEY ONLY (no IV needed in CBC):
#          P_i = AES_dec(C_i) XOR C_{i-1}   for i >= 1
# ---------------------------------------------------------------------------
zero_iv = AES.new(KEY, AES.MODE_CBC, iv=b"\x00" * 16).decrypt(CT)
print("[*] blocks 1-2 (key only):", zero_iv[16:])
# -> b't0_l34rn_fr0M_n0T_t0_l1V3_1n}\x03\x03\x03'   (valid PKCS#7 pad of 3)

# ---------------------------------------------------------------------------
# Step 2 - block 0 needs the IV.  P_0 = AES_dec(C_0) XOR IV.
#          Known plaintext "CMO{" gives us IV[0:4] directly.
# ---------------------------------------------------------------------------
dec0 = AES.new(KEY, AES.MODE_ECB).decrypt(CT[:16])   # AES_dec(C_0)
iv_prefix = bytes(dec0[i] ^ b for i, b in enumerate(b"CMO{"))
print("[*] IV[0:4] from known 'CMO{':", iv_prefix)   # -> b'0000'  (zero-padded decimal)

# ---------------------------------------------------------------------------
# Step 3 - the real IV is the program's amalgamated timestamp value, zero
#          padded to 16 ASCII digits.  The true amalgam is 537068053.
#          (NOTE: the all-digit constraint alone does NOT uniquely fix block 0
#           -- multiple readable leetspeak strings yield valid all-digit IVs;
#           only the real IV value disambiguates the first character.)
# ---------------------------------------------------------------------------
IV = b"%016d" % 537068053             # -> b'0000000537068053'
pt = AES.new(KEY, AES.MODE_CBC, iv=IV).decrypt(CT)

# strip PKCS#7
pad = pt[-1]
flag = pt[:-pad] if 1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad else pt
print("[*] IV:", IV, "(amalgam =", int(IV), ")")
print("[+] FLAG:", flag.decode())

assert flag == b"CMO{5h3_p4St_1s_t0_l34rn_fr0M_n0T_t0_l1V3_1n}"
print("[+] verified.")
