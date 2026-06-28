/*
 * BitCalc — solver
 *
 * The binary reads a 32-bit integer and uses each bit to write either
 * 0x05 (add) or 0x2d (sub) into a 160-byte code region, one byte per
 * 5-byte slot. It then calls that region, which runs 32 add/sub operations
 * on a starting EAX value and compares the result to a target.
 *
 * This program searches all 2^32 sign assignments via recursive DFS and
 * prints every integer input that satisfies the equation.
 *
 * Build:  gcc -O2 -o solve solve.c
 * Run:    ./solve
 * Use:    echo "<result>" | ./main
 */

#include <stdio.h>
#include <stdint.h>

/* First instruction in the generated code: mov $0x3df2f794,%eax */
static int start = 0x3df2f794;

/*
 * 32 immediate constants embedded in the binary's code region.
 * Extracted with extract.gdb: one 4-byte value per 5-byte slot,
 * at offsets +1, +6, +11, ... from the region base.
 */
static int values[32] = {
    0x52ae22f2, 0xbf409bcc, 0x46417dc1, 0x25f7d9a1,
    0xef83a7ce, 0x2dd63e8e, 0x584a1ec5, 0x8e58e1df,
    0xf2705f70, 0x2e94ef1e, 0x3ca9e080, 0xa617b5df,
    0x29ae9c3d, 0x7461ed52, 0x7125faac, 0x65dfffd6,
    0x97f1f41c, 0x6f4e0648, 0xd803e5d0, 0xf358f0eb,
    0xbc3b30c7, 0x585685f8, 0x2a9cc47c, 0x7f03d175,
    0xc1d942ae, 0x174c7d4f, 0xb7d004f0, 0xbec8b077,
    0x8ce8eaa2, 0x2510e330, 0x4aed0eee, 0x4043cd91
};

/* Target: cmp $0x7a612770,%eax in the generated code */
static int result = 0x7a612770;

/*
 * Reverse all 32 bits of x.
 *
 * The binary's loop consumes input bits LSB-first (SAR shifts the LSB
 * out each iteration), so input bit 0 drives operation 0. The recursion
 * below accumulates choices MSB-first into `marker`, so bitrev() is
 * needed to convert the marker back to the correct input integer.
 */
static uint32_t bitrev(uint32_t x) {
    uint32_t r = 0;
    for (int i = 0; i < 32; i++)
        r |= ((x >> i) & 1u) << (31 - i);
    return r;
}

/*
 * Recursive DFS over all sign assignments.
 *
 *   level  : current depth (0 = first value, 31 = last value)
 *   sum    : running EAX value accumulated so far
 *   marker : bit pattern of choices made so far (1=add, 0=sub)
 *            accumulated MSB-first; bitrev() converts to input integer
 */
static void search(unsigned level, int sum, uint32_t marker) {
    if (level == 31) {
        /* Try both signs for the last value and check against target */
        if (sum + values[level] == result)
            printf("%d\n", (int)bitrev((marker << 1) | 1u));  /* last bit = 1 (add) */
        if (sum - values[level] == result)
            printf("%d\n", (int)bitrev( marker << 1));         /* last bit = 0 (sub) */
        return;
    }
    search(level + 1, sum + values[level], (marker << 1) | 1u);  /* add branch */
    search(level + 1, sum - values[level],  marker << 1);         /* sub branch */
}

int main(void) {
    search(0, start, 0);
    return 0;
}
