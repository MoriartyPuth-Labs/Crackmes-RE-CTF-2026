# Matryoshka v2 — emulation harness
#
# Emulates the CHECK shellcode from Doll.dll (RT_RCDATA "CHECK") using
# Unicorn Engine to analyse the validation logic.
#
# Architecture recap:
#   LicenseChecker.exe reads license.bin, calls Doll.dll!CheckPassword
#   CheckPassword:
#     1. Loads CHECK shellcode into RWX memory, calls it with license[0..31]
#     2. If shellcode returns non-zero: RC4-decrypts MATRYOSHKA with license[0..31]
#        then loads the resulting PE and calls its CheckPassword(license[32..])
#
# The CHECK shellcode is 1.3 MB of x86-64 with opaque-predicate obfuscation
# (~1 real instruction per 500 shellcode bytes).
#
# Usage:
#   pip install unicorn capstone
#   python solve.py
#
# Flag (confirmed from official post-CTF disclosure):
#   CMO{1NsiD3_EV3RY_stOrY_lIe$_an0TH3r_s70Ry_WAITiNG_7o_bE_oPEn3d}

import struct
from unicorn import *
from unicorn.x86_const import *
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

DLL_PATH  = "Doll.dll"
SC_OFFSET = 0x3CF4       # file offset of CHECK shellcode
SC_SIZE   = 0x14A2DE     # size of CHECK shellcode

SC_BASE  = 0x10000000
LIC_BASE = 0x20000000
STK_BASE = 0x30000000
STK_SIZE = 0x200000      # 2 MB stack

with open(DLL_PATH, "rb") as f:
    f.seek(SC_OFFSET)
    shellcode = f.read(SC_SIZE)

assert shellcode[:5] == b"\xe9\xe5\x51\x04\x00", "unexpected shellcode header"

entry_off = struct.unpack_from("<i", shellcode, 1)[0] + 5   # 0x451EA
sc_pages  = (SC_SIZE + 0xFFF) & ~0xFFF
ret_sent  = SC_BASE + sc_pages                               # sentinel return addr

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = False


def disasm1(off):
    if 0 <= off < SC_SIZE:
        for i in md.disasm(shellcode[off:off + 15], SC_BASE + off):
            return i.mnemonic + " " + i.op_str
    return "???"


def emulate(license32: bytes, max_insns: int = 1_000_000):
    """
    Emulate CHECK shellcode with the given 32-byte license key.
    Returns (insn_count, rax_at_return, license_reads, cmp_events).

    license_reads  : list of byte offsets within license32 that were read
    cmp_events     : list of (insn_num, sc_offset, rax, rdx) for cmp/test
    """
    assert len(license32) >= 32

    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(SC_BASE, sc_pages + 0x1000)
    mu.mem_write(SC_BASE, shellcode)
    mu.mem_map(LIC_BASE, 0x1000)
    mu.mem_write(LIC_BASE, license32[:64].ljust(64, b"\x00"))
    mu.mem_map(STK_BASE, STK_SIZE)

    rsp = STK_BASE + STK_SIZE - 0x400
    mu.reg_write(UC_X86_REG_RSP, rsp)
    mu.reg_write(UC_X86_REG_RCX, LIC_BASE)
    mu.mem_write(rsp, struct.pack("<Q", ret_sent))

    insns      = [0]
    ret_rax    = [0]
    lic_reads  = []
    cmp_events = []
    cur_rip    = [0]

    def hook_code(mu, addr, sz, ud):
        insns[0] += 1
        cur_rip[0] = addr
        if addr == ret_sent:
            ret_rax[0] = mu.reg_read(UC_X86_REG_RAX)
            mu.emu_stop()
            return
        off = addr - SC_BASE
        if 0 <= off < SC_SIZE:
            dis = disasm1(off)
            if dis.startswith(("cmp", "test")):
                rax = mu.reg_read(UC_X86_REG_RAX)
                rdx = mu.reg_read(UC_X86_REG_RDX)
                cmp_events.append((insns[0], off, rax, rdx))

    def hook_mem_read(mu, acc, addr, sz, val, ud):
        if LIC_BASE <= addr < LIC_BASE + 64:
            lic_reads.append(addr - LIC_BASE)

    def hook_mem_err(mu, acc, addr, sz, val, ud):
        ret_rax[0] = mu.reg_read(UC_X86_REG_RAX)
        mu.emu_stop()
        return False

    mu.hook_add(UC_HOOK_CODE, hook_code)
    mu.hook_add(UC_HOOK_MEM_READ, hook_mem_read)
    mu.hook_add(
        UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED |
        UC_HOOK_MEM_FETCH_UNMAPPED, hook_mem_err,
    )

    try:
        mu.emu_start(SC_BASE + entry_off, ret_sent + 1,
                     timeout=0, count=max_insns)
    except UcError:
        ret_rax[0] = mu.reg_read(UC_X86_REG_RAX)

    return insns[0], ret_rax[0], sorted(set(lic_reads)), cmp_events


def show_cmp_summary(cmp_events, label=""):
    rdx_vals = sorted({rdx for _, _, _, rdx in cmp_events if rdx > 0 and rdx < 0xFFFF_FFFF_FFFF_FFFF})
    print(f"  [{label}] {len(cmp_events)} cmp/test events  unique rdx>0: {len(rdx_vals)}")
    if rdx_vals:
        print(f"    First 8 rdx: {[hex(v) for v in rdx_vals[:8]]}")


if __name__ == "__main__":
    print("=" * 64)
    print("CHECK shellcode emulation harness")
    print(f"  Shellcode size : {SC_SIZE:#x}")
    print(f"  Entry offset   : {entry_off:#x}")
    print(f"  Load base      : {SC_BASE:#x}")
    print()

    # ── baseline: all-null key (immediate fail) ──────────────────────
    cnt, rax, reads, cmps = emulate(bytes(32))
    print(f"all-null key   : {cnt} insns  rax={rax:#x}  reads={reads}")
    show_cmp_summary(cmps, "null")

    # ── 32×0x41 key (full validation path, ~444 k insns) ─────────────
    cnt, rax, reads, cmps = emulate(b"\x41" * 32, max_insns=500_000)
    print(f"'A'×32 key     : {cnt} insns  rax={rax:#x}  reads={reads}")
    show_cmp_summary(cmps, "A×32")

    # ── differential: byte[0]=0x00 vs 0x01 ───────────────────────────
    cnt0, _, _, _ = emulate(bytes(32))
    cnt1, _, _, _ = emulate(b"\x01" + bytes(31))
    print(f"\nbyte[0]=0x00 : {cnt0} insns")
    print(f"byte[0]=0x01 : {cnt1} insns  (+{cnt1-cnt0})")

    # ── the 32 expected comparison values (rdx at cmp rax,rdx) ───────
    print("\n" + "=" * 64)
    print("Expected rdx values at `cmp rax, rdx` (A×32 run):")
    _, _, _, cmps = emulate(b"\x41" * 32, max_insns=500_000)
    expected = sorted({rdx for _, off, _, rdx in cmps
                       if disasm1(off).startswith("cmp rax, rdx") and rdx > 0})
    for i, v in enumerate(expected):
        print(f"  [{i:2d}]  {v:#010x}")

    print()
    print("Flag (official post-CTF disclosure):")
    print("  CMO{1NsiD3_EV3RY_stOrY_lIe$_an0TH3r_s70Ry_WAITiNG_7o_bE_oPEn3d}")
