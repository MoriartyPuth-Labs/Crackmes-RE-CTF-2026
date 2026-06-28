import distorm3

# Scan the binary for RET instructions not preceded by XOR EAX,EAX.
# Dead ends all look like: 31 C0 C3 (XOR EAX,EAX; RET -> return 0)
# The exit node will have something else before the RET (e.g. MOV EAX,1)

filename = "maze"
offset   = 0xb0          # skip the 29-instruction entry stub
length   = distorm3.Decode64Bits

code     = open(filename, "rb").read()[offset:]
prev     = None
iterable = distorm3.DecodeGenerator(offset, code, length)

for (off, size, instruction, hexdump) in iterable:
    if hexdump == "c3" and prev is not None and prev[1] != "31c0":
        print("-------------------------------------------")
        print("%.8x: %-32s %s" % prev)
        print("%.8x: %-32s %s" % (off, hexdump, instruction))
        print("-------------------------------------------")
    prev = (off, hexdump, instruction)
