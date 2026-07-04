# Crackmes.one RE CTF 2026 — Writeups

Full writeups with proof-of-concept code, reproduction steps, and tooling notes. **Click a challenge to open its writeup.**

| # | Challenge | Category | Flag / Solution |
|---|-----------|----------|-----------------|
| 1 | [**Maze**](writeups/maze/) | Reversing — Pure-assembly BFS graph traversal | `<684-char move sequence>` (see writeup) |
| 2 | [**Bubbly**](writeups/bubbly/) | Reversing — Bubble sort swap-index trace | `2 3 4 5 7 9 10 13 ...` (22 indices, see writeup) |
| 3 | [**BitCalc**](writeups/bitcalc/) | Reversing — Self-modifying x86, recursive DFS | `374274518` (one of 4 valid inputs) |
| 4 | [**date_of_birth**](writeups/date_of_birth/) | Reversing — Anti-debug SIGSTOP + signed byte overflow | `6/29/1898` (example for 2026-06-28) |
| 5 | [**FLRSCRNSVR**](writeups/FLRSCRNSVR/) | Reversing — Windows screensaver, substitution + XOR + reverse | `CMO{frogt4s7ic_r3vers1ng}` |
| 6 | [**wallpaper**](writeups/wallpaper/) | Reversing — 15-puzzle on hex nibbles, A* solver | `CMO{<37-char move sequence>}` (see writeup) |
| 7 | [**Matryoshka v2**](writeups/Matryoshka_v2/) | Reversing — 4-layer nested PE, 1.3 MB VM-obfuscated shellcode, RC4 | `CMO{1NsiD3_EV3RY_stOrY_lIe$_an0TH3r_s70Ry_WAITiNG_7o_bE_oPEn3d}` (see writeup) |
| 8 | [**httpd**](writeups/httpd/) | Reversing / Malware — Go port-knocker masquerading as web server, ICMP magic packet, AES-128-CBC | `CMO{fUn_w1th_m4g1c_p4ck3t5}` |
| 9 | [**a matter of time**](writeups/a_matter_of_time/) | Reversing — Windows PE, timestamp-keyed decryption, time hook + memory dump | `CMO{5h3_p4St_1s_t0_l34rn_fr0M_n0T_t0_l1V3_1n}` |
| 10 | [**CryptPad**](writeups/cryptPad/) | Reversing / Crypto — custom cipher on `flag.enc`, roll-your-own crypto | `CMO{r0ll_y0ur_0wn_b4d_c0d3}` |
| 11 | [**connected**](writeups/connected/) | Reversing / Crackme — automotive security binary, static analysis | `CMO{secret_code_v9hcdkd2}` |
| 12 | [**what did you type**](writeups/what_did_you_type/) | Forensics / RE — USB HID keylog capture, HID scan-code decode | `CMO{Dumb357_P3r50n_1n_7h3_M1lky_W4y_!!!}` |

Each folder contains a self-contained `README.md` writeup plus a runnable solver script.

```
writeups/
├── maze/            README.md  +  solve.py  +  targets.py
├── bubbly/          README.md  +  main.py
├── bitcalc/         README.md  +  solve.c   +  extract.gdb
├── date_of_birth/   README.md  +  keygen.py
├── FLRSCRNSVR/      README.md  +  solve.py
├── wallpaper/       README.md  +  solve.py
├── Matryoshka_v2/   README.md  +  solve.py
├── httpd/           README.md  +  httpd_writeup.txt
├── a_matter_of_time/ README.md  +  solve.py  +  memdump.py  +  timehook.py
├── cryptPad/        WRITEUP.md  +  solve.py
├── connected/       README.md  +  solve.py
└── what_did_you_type/ WRITEUP.md  +  solve.py  +  decode_hid.py
```

---

## Tooling used

- **Disassembly / decompilation:** Ghidra (Windows PE), GDB + Python API (ELF dynamic analysis), `objdump`, `file`, `strings`
- **Python 3:** all solvers — BFS/A* graph search, self-modifying code reconstruction, keygen math, cipher inversion
- **C:** BitCalc recursive DFS solver (`gcc -O2`)
- **distorm3:** disassembly library for scanning Maze exit nodes
- **Platform:** Linux (WSL2) for ELF challenges; Windows for FLRSCRNSVR screensaver

```bash
pip install distorm3
gcc -O2 -o solve writeups/bitcalc/solve.c
```

---

## Lessons / takeaways

- **Maze** — A pure-assembly binary with no symbols is just a pattern in bytes; once you find the 106-byte node tile, BFS solves it mechanically.
- **Bubbly** — Trace the sort algorithm rather than reversing the check; reconstruct the original array from the sorted goal, then replay the sort to emit swap indices.
- **BitCalc** — Self-modifying code is only scary until you dump the immediate constants; after that it's 2³² DFS branches prunable with a bit-reversal trick.
- **date_of_birth** — Anti-debug SIGSTOP is trivially bypassed; the real challenge is the signed-byte overflow in the year check (`0x7F+1 = -128`), which collapses an infinite search space to a handful of dates.
- **FLRSCRNSVR** — Registry-backed screensavers still store plaintext transform parameters in `.rodata`; three-step invertible ciphers invert in three lines of Python.
- **wallpaper** — Hardcoded puzzle states in `.rodata` give away the entire challenge; Manhattan-distance A* finds a 37-move solution instantly.
- **httpd** — The binary name is a decoy; a background goroutine opens a libpcap sniffer and gates on a magic ICMP knock. The key derivation touches only a few packet header bytes, making the key space tiny enough to brute-force offline without any FreeBSD host.
- **a matter of time** — Timestamp-keyed decryption sounds time-sensitive but isn't; hook `GetSystemTime` / `GetLocalTime` to feed a fixed date, then dump the decrypted flag from memory.
- **CryptPad** — Roll-your-own crypto on `flag.enc`; static reversal of the custom cipher is enough to recover the plaintext without ever running the binary.
- **connected** — Automotive crackme; static analysis of the validation routine yields the secret code directly.
- **what did you type** — USB HID keylog capture; decode HID scan codes to ASCII and read back what was typed.

---

## 👤 Author

**MoriartyPuth** — Offensive Security

![GitHub](https://img.shields.io/badge/GitHub-MoriartyPuth-181717?logo=github)

</div>

> ⚠️ **Disclaimer.** _This document is a writeup produced from ctf challenges
> All challenge details pertain strictly to intentionally vulnerable, isolated competition infrastructure
> documentation-reserved placeholders. It contains no client data, no live targets and no
> novel exploit code. Techniques shown are standard, publicly documented, and provided for
> educational and defensive purposes only. Do not test any system you do not own or lack
> explicit written authorisation to assess._
