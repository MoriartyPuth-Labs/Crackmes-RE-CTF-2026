import ctypes as C, ctypes.wintypes as W, sys, threading, time, re
k32=C.WinDLL('kernel32',use_last_error=True)
EXE=r"C:\Users\moriarty\Downloads\69a290ce7a778cfffbfb67c6\a_matter_of_time.exe"
TARGET_FT=137919572470000000
DEBUG_ONLY_THIS_PROCESS=0x2; STARTF_USESTDHANDLES=0x100
DBG_CONTINUE=0x00010002; DBG_EXC_NOT=0x80010001; BP=0x80000003
class STARTUPINFO(C.Structure):
    _fields_=[("cb",W.DWORD),("a",W.LPWSTR),("b",W.LPWSTR),("c",W.LPWSTR),("dwX",W.DWORD),("dwY",W.DWORD),("dwXS",W.DWORD),("dwYS",W.DWORD),("dwXC",W.DWORD),("dwYC",W.DWORD),("dwFill",W.DWORD),("dwFlags",W.DWORD),("wShow",W.WORD),("cb2",W.WORD),("lpR2",C.POINTER(W.BYTE)),("hI",W.HANDLE),("hO",W.HANDLE),("hE",W.HANDLE)]
class PI(C.Structure): _fields_=[("hProcess",W.HANDLE),("hThread",W.HANDLE),("pid",W.DWORD),("tid",W.DWORD)]
class ER(C.Structure): pass
ER._fields_=[("Code",W.DWORD),("Flags",W.DWORD),("Rec",C.POINTER(ER)),("Addr",C.c_void_p),("Np",W.DWORD),("Info",C.c_ulonglong*15)]
class EDI(C.Structure): _fields_=[("ER",ER),("First",W.DWORD)]
class U(C.Union): _fields_=[("Exc",EDI),("raw",C.c_byte*200)]
class DE(C.Structure): _fields_=[("code",W.DWORD),("pid",W.DWORD),("tid",W.DWORD),("u",U)]
class CTX(C.Structure):
    _fields_=[("P",C.c_ulonglong*6),("ContextFlags",W.DWORD),("MxCsr",W.DWORD),("SegCs",W.WORD),("SegDs",W.WORD),("SegEs",W.WORD),("SegFs",W.WORD),("SegGs",W.WORD),("SegSs",W.WORD),("EFlags",W.DWORD),("Dr",C.c_ulonglong*6),("Rax",C.c_ulonglong),("Rcx",C.c_ulonglong),("Rdx",C.c_ulonglong),("Rbx",C.c_ulonglong),("Rsp",C.c_ulonglong),("Rbp",C.c_ulonglong),("Rsi",C.c_ulonglong),("Rdi",C.c_ulonglong),("R8",C.c_ulonglong),("R9",C.c_ulonglong),("R10",C.c_ulonglong),("R11",C.c_ulonglong),("R12",C.c_ulonglong),("R13",C.c_ulonglong),("R14",C.c_ulonglong),("R15",C.c_ulonglong),("Rip",C.c_ulonglong),("fr",C.c_byte*512)]
CFLAGS=0x100000|1|2
for f in (k32.GetModuleHandleW,): f.restype=C.c_void_p; f.argtypes=[C.c_wchar_p]
k32.GetProcAddress.restype=C.c_void_p; k32.GetProcAddress.argtypes=[C.c_void_p,C.c_char_p]
hntdll=k32.GetModuleHandleW("ntdll.dll")
NQST=k32.GetProcAddress(hntdll,b"NtQuerySystemTime")
class SA(C.Structure): _fields_=[("n",W.DWORD),("sd",C.c_void_p),("inh",W.BOOL)]
sa=SA(C.sizeof(SA),None,True)
o_r=W.HANDLE();o_w=W.HANDLE();i_r=W.HANDLE();i_w=W.HANDLE()
k32.CreatePipe(C.byref(o_r),C.byref(o_w),C.byref(sa),0)
k32.CreatePipe(C.byref(i_r),C.byref(i_w),C.byref(sa),0)
k32.SetHandleInformation(o_r,1,0); k32.SetHandleInformation(i_w,1,0)
si=STARTUPINFO();si.cb=C.sizeof(si);si.dwFlags=STARTF_USESTDHANDLES;si.hI=i_r;si.hO=o_w;si.hE=o_w
pi=PI()
k32.CreateProcessW(EXE,None,None,None,True,DEBUG_ONLY_THIS_PROCESS,None,None,C.byref(si),C.byref(pi))
k32.WriteFile(i_w,b"\r\n\r\n\r\n\r\n",8,C.byref(W.DWORD()),None)
out=bytearray()
def reader():
    buf=(C.c_char*4096)();n=W.DWORD()
    while k32.ReadFile(o_r,buf,4096,C.byref(n),None) and n.value: out.extend(buf.raw[:n.value])
threading.Thread(target=reader,daemon=True).start()
def rpm(a,n):
    b=(C.c_char*n)();r=C.c_size_t()
    if k32.ReadProcessMemory(pi.hProcess,C.c_void_p(a),b,n,C.byref(r)): return b.raw[:r.value]
    return b""
def wpm(a,data): k32.WriteProcessMemory(pi.hProcess,C.c_void_p(a),data,len(data),C.byref(C.c_size_t()))
def scanmem(label):
    class MBI(C.Structure):
        _fields_=[("Base",C.c_void_p),("Alloc",C.c_void_p),("Prot",W.DWORD),("a",W.DWORD),("Size",C.c_size_t),("State",W.DWORD),("P2",W.DWORD),("Type",W.DWORD)]
    mbi=MBI();addr=0;hits=[]
    k32.VirtualQueryEx.restype=C.c_size_t
    while addr < 0x7fffffff0000:
        if not k32.VirtualQueryEx(pi.hProcess,C.c_void_p(addr),C.byref(mbi),C.sizeof(mbi)): break
        base=mbi.Base or 0; size=mbi.Size or 0x1000
        MEM_COMMIT=0x1000
        if mbi.State==MEM_COMMIT and (mbi.Prot&0xFF) in (0x02,0x04,0x20,0x40,0x08,0x10,0x80):
            data=rpm(base,min(size,8*1024*1024))
            for m in re.finditer(rb'[\x20-\x7e]{6,}',data):
                s=m.group()
                hits.append(s)
        addr=base+size
    return hits
orig={}; installed=False; de=DE(); ftb=TARGET_FT.to_bytes(8,'little'); count=0; dumped=False
while True:
    if not k32.WaitForDebugEvent(C.byref(de),20000): break
    code=de.code; status=DBG_CONTINUE
    if code==1:
        er=de.u.Exc.ER; ec=er.Code
        if ec==BP:
            addr=er.Addr
            if not installed:
                orig[NQST]=rpm(NQST,1); wpm(NQST,b"\xCC"); installed=True
            elif addr==NQST:
                ctx=CTX();ctx.ContextFlags=CFLAGS;k32.GetThreadContext(pi.hThread,C.byref(ctx))
                wpm(ctx.Rcx,ftb)
                count+=1
                if count==2 and not dumped:
                    # by now intro+gate strings built; dump memory
                    hits=scanmem("at_nqst2")
                    open("memdump_strings.txt","wb").write(b"\n".join(hits))
                    dumped=True
                ret=int.from_bytes(rpm(ctx.Rsp,8),'little'); ctx.Rip=ret; ctx.Rsp+=8
                k32.SetThreadContext(pi.hThread,C.byref(ctx))
            else: status=DBG_EXC_NOT
        else: status=DBG_EXC_NOT
    elif code==5:
        if not dumped:
            hits=scanmem("exit"); open("memdump_strings.txt","wb").write(b"\n".join(hits)); dumped=True
        k32.ContinueDebugEvent(de.pid,de.tid,DBG_CONTINUE); break
    k32.ContinueDebugEvent(de.pid,de.tid,status)
time.sleep(0.5); k32.CloseHandle(o_w)
print("done, nqst hits",count)
