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

Each folder contains a self-contained `README.md` writeup plus a runnable solver script.

```
writeups/
├── maze/           README.md  +  solve.py  +  targets.py
├── bubbly/         README.md  +  main.py
├── bitcalc/        README.md  +  solve.c   +  extract.gdb
├── date_of_birth/  README.md  +  keygen.py
├── FLRSCRNSVR/     README.md  +  solve.py
└── wallpaper/      README.md  +  solve.py
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

---

## Author

<div align="center">

**Eav Puthcambo**
<br/>
AUPP Cybersecurity Programme
<br/>
American University of Phnom Penh

[![GitHub](https://img.shields.io/badge/GitHub-MoriartyPuth--Labs-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/MoriartyPuth-Labs)

</div>
