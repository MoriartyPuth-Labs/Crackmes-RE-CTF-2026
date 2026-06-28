# FLRSCRNSVR — flag recovery
#
# Inverts the three-step handling_input transform applied to the registry
# Quak value to recover the 25-character plaintext flag.
#
# handling_input forward pipeline (what the binary does to your input):
#   1. Substitution: map each wchar via str1 → str2 index lookup
#   2. XOR: input[i] ^= (i + FLARERALF[i % 9])
#   3. Reverse: swap input[0..11] with input[24..13]
#
# To recover the flag we apply the inverse steps in reverse order:
#   3'. Reverse the Quak array           (self-inverse: applying twice = identity)
#   2'. XOR each entry again             (self-inverse: XOR with the same key = identity)
#   1'. Map each wchar via str2 → str1   (inverse substitution)
#
# Usage: python solve.py

import struct

# Quak value as stored in HKCU\Software\FLRSCRNSVR\Quak (50 bytes, UTF-16LE)
quak_hex = (
    "3c 00 51 00 6a 00 09 00 02 00 07 00 25 00 03 00 "
    "30 00 08 00 04 00 29 00 68 00 24 00 01 00 24 00 "
    "18 00 6b 00 77 00 0f 00 70 00 36 00 02 00 0e 00 "
    "0b 00"
)
quak_bytes = bytes.fromhex(quak_hex.replace(" ", ""))

# XOR key embedded in the binary as a wide-string literal
flareralf = bytes.fromhex("464c41524552414c46")   # "FLARERALF" (9 bytes)

# Substitution tables — paired character-for-character (str1[i] ↔ str2[i])
str1 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789}_{=-"
str2 = "-={_}9876543210ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba"

# Inverse substitution map: str2 char → the str1 char at the same index
inv_sub = dict(zip(str2, str1))

# --- Unpack as 25 unsigned 16-bit little-endian values ---
quak = list(struct.unpack("<25H", quak_bytes))

# Step 3' — undo the reversal
quak.reverse()

# Step 2' — undo the XOR (self-inverse: same operation recovers original)
for i in range(len(quak)):
    quak[i] ^= i + flareralf[i % len(flareralf)]

# Step 1' — undo the substitution (look up in inverse map)
flag = "".join(inv_sub[chr(v)] for v in quak)

print(flag)
