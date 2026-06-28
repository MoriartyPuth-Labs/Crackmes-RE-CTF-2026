# Maze — BFS solver
# Finds the shortest input string that makes the binary return AL=1 (Well done!)
#
# How the maze works:
#   Every node is the same 106-byte block of assembly.
#   Reading digit 1/2/3/4 jumps to addr+delta for that digit.
#   Dead ends contain XOR EAX,EAX; RET (return 0).
#   The single exit node at 0x0CB2C8 contains MOV EAX,1; RET.

# 106-byte node pattern (same code repeated across the binary)
pattern = (
    b"\x8A\x07\x48\xFF\xC7\x3C\x0A\x74\x5E\x2C\x30\x3C\x01\x75\x0E"
    b"\x48\xC7\xC3\xFF\xFF\xFF\xFF\xB9\x65\x00\x00\x00\xEB\x32\x3C\x02"
    b"\x75\x0E\x48\xC7\xC3\xFF\xFF\xFF\xFF\xB9\x01\x00\x00\x00\xEB\x20"
    b"\x3C\x03\x75\x0C\xBB\x01\x00\x00\x00\xB9\x01\x00\x00\x00\xEB\x10"
    b"\x3C\x04\x75\x24\xBB\x01\x00\x00\x00\xB9\x65\x00\x00\x00\xEB\x00"
    b"\x48\x0F\xAF\xD9\x48\x6B\xDB\x6A\x48\x8D\x05\xF9\xFF\xFF\xFF\x48"
    b"\x83\xE8\x57\x48\x01\xD8\xFF\xE0\x31\xC0\xC3"
)

dead_end    = b"\x31\xC0\xC3"   # XOR EAX,EAX; RET
start       = 0x0716D0          # entry call target
exit_node   = 0x0CB2C8          # only node that returns 1
lower_bound = 0x00013B
upper_bound = 0x1080A8

# Digit → address delta
moves = [
    (-0x29D2, "1"),
    (-0x006A, "2"),
    ( 0x006A, "3"),
    ( 0x29D2, "4"),
]

maze    = open("maze", "rb").read()
visited = {start}
queue   = [(start, "")]

while queue:
    addr, path = queue.pop(0)

    if addr == exit_node:
        print("[+] Solution found!")
        print("[+] Input length: %d" % len(path))
        print("[+] Input:\n%s" % path)
        break

    if not (lower_bound <= addr <= upper_bound):
        continue

    if maze[addr : addr + len(dead_end)] == dead_end:
        continue

    if maze[addr : addr + len(pattern)] != pattern:
        print("[!] Unexpected code at %s — manual analysis needed" % hex(addr))
        break

    for delta, move_char in moves:
        next_addr = addr + delta
        if next_addr not in visited:
            visited.add(next_addr)
            queue.append((next_addr, path + move_char))
