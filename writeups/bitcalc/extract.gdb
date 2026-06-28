# extract.gdb — dump the 32 immediate constants from the generated code region
#
# Usage:
#   1. Set a breakpoint at the generated code entry (e.g. 0x555555755020)
#   2. Run the binary with any integer input (e.g. run <<< "0")
#   3. When the breakpoint hits, call:
#        display5 0x555555755020 0x5555557550c5
#   4. Copy the 32 printed hex values into solve.c → values[]
#
# The region base and end addresses vary per run due to ASLR.
# Disable ASLR first for reproducible addresses:
#   set disable-randomization on   (gdb default — usually already off in gdb)

define display5
  set $cur  = $arg0 + 1     # skip the opcode byte (0x05 or 0x2d), land on the 4-byte immediate
  set $stop = $arg1
  while $cur < $stop
    printf "0x%08x\n", *(unsigned int *) $cur
    set $cur = $cur + 5
  end
end

document display5
  Dump the 32-bit immediate values from the 5-byte add/sub slots in the
  generated code region.  Each slot is: [opcode:1] [imm32:4].
  Usage: display5 <region_base> <region_end>
  Example: display5 0x555555755020 0x5555557550c5
end
