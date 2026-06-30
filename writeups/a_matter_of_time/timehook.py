import ctypes as C, ctypes.wintypes as W, sys, threading, time

k32=C.WinDLL('kernel32',use_last_error=True)
EXE=r"C:\Users\moriarty\Downloads\69a290ce7a778cfffbfb67c6\a_matter_of_time.exe"
TARGET_FT=int(sys.argv[1],0) if len(sys.argv)>1 else 137919572470000000  # unix 0x7fffffff

DEBUG_ONLY_THIS_PROCESS=0x2
CREATE_NEW_CONSOLE=0x10
STARTF_USESTDHANDLES=0x100
INFINITE=0xFFFFFFFF
DBG_CONTINUE=0x00010002
DBG_EXCEPTION_NOT_HANDLED=0x80010001
EXCEPTION_BREAKPOINT=0x80000003

class STARTUPINFO(C.Structure):
    _fields_=[("cb",W.DWORD),("lpReserved",W.LPWSTR),("lpDesktop",W.LPWSTR),
    ("lpTitle",W.LPWSTR),("dwX",W.DWORD),("dwY",W.DWORD),("dwXSize",W.DWORD),
    ("dwYSize",W.DWORD),("dwXCountChars",W.DWORD),("dwYCountChars",W.DWORD),
    ("dwFillAttribute",W.DWORD),("dwFlags",W.DWORD),("wShowWindow",W.WORD),
    ("cbReserved2",W.WORD),("lpReserved2",C.POINTER(W.BYTE)),
    ("hStdInput",W.HANDLE),("hStdOutput",W.HANDLE),("hStdError",W.HANDLE)]
class PROCESS_INFORMATION(C.Structure):
    _fields_=[("hProcess",W.HANDLE),("hThread",W.HANDLE),("dwProcessId",W.DWORD),("dwThreadId",W.DWORD)]
class EXCEPTION_RECORD(C.Structure): pass
EXCEPTION_RECORD._fields_=[("ExceptionCode",W.DWORD),("ExceptionFlags",W.DWORD),
    ("ExceptionRecord",C.POINTER(EXCEPTION_RECORD)),("ExceptionAddress",C.c_void_p),
    ("NumberParameters",W.DWORD),("ExceptionInformation",C.c_ulonglong*15)]
class EXCEPTION_DEBUG_INFO(C.Structure):
    _fields_=[("ExceptionRecord",EXCEPTION_RECORD),("dwFirstChance",W.DWORD)]
class DEBUG_EVENT_U(C.Union):
    _fields_=[("Exception",EXCEPTION_DEBUG_INFO),("raw",C.c_byte*200)]
class DEBUG_EVENT(C.Structure):
    _fields_=[("dwDebugEventCode",W.DWORD),("dwProcessId",W.DWORD),("dwThreadId",W.DWORD),("u",DEBUG_EVENT_U)]

class CONTEXT(C.Structure):
    _fields_=[("P1Home",C.c_ulonglong),("P2Home",C.c_ulonglong),("P3Home",C.c_ulonglong),
    ("P4Home",C.c_ulonglong),("P5Home",C.c_ulonglong),("P6Home",C.c_ulonglong),
    ("ContextFlags",W.DWORD),("MxCsr",W.DWORD),
    ("SegCs",W.WORD),("SegDs",W.WORD),("SegEs",W.WORD),("SegFs",W.WORD),("SegGs",W.WORD),("SegSs",W.WORD),
    ("EFlags",W.DWORD),
    ("Dr0",C.c_ulonglong),("Dr1",C.c_ulonglong),("Dr2",C.c_ulonglong),("Dr3",C.c_ulonglong),
    ("Dr6",C.c_ulonglong),("Dr7",C.c_ulonglong),
    ("Rax",C.c_ulonglong),("Rcx",C.c_ulonglong),("Rdx",C.c_ulonglong),("Rbx",C.c_ulonglong),
    ("Rsp",C.c_ulonglong),("Rbp",C.c_ulonglong),("Rsi",C.c_ulonglong),("Rdi",C.c_ulonglong),
    ("R8",C.c_ulonglong),("R9",C.c_ulonglong),("R10",C.c_ulonglong),("R11",C.c_ulonglong),
    ("R12",C.c_ulonglong),("R13",C.c_ulonglong),("R14",C.c_ulonglong),("R15",C.c_ulonglong),
    ("Rip",C.c_ulonglong),
    ("fr:",C.c_byte*512)]
CONTEXT_AMD64=0x100000; CONTEXT_CONTROL=CONTEXT_AMD64|1; CONTEXT_INTEGER=CONTEXT_AMD64|2
CFLAGS=CONTEXT_CONTROL|CONTEXT_INTEGER

# resolve hook addresses (kernel32 base identical across processes this boot)
k32.GetModuleHandleW.restype=C.c_void_p
k32.GetModuleHandleW.argtypes=[C.c_wchar_p]
k32.GetProcAddress.argtypes=[C.c_void_p,C.c_char_p]
k32.GetModuleHandleW.restype=C.c_void_p
k32.GetModuleHandleW.argtypes=[C.c_wchar_p]
k32.GetProcAddress.argtypes=[C.c_void_p,C.c_char_p]
k32.GetProcAddress.restype=C.c_void_p
hk=k32.GetModuleHandleW("kernel32.dll")
hntdll=k32.GetModuleHandleW("ntdll.dll")
HOOKS={}; KIND={}
for nm,kind in (("GetSystemTimeAsFileTime","ft"),("GetSystemTimePreciseAsFileTime","ft"),
                ("GetSystemTime","st"),("GetLocalTime","st")):
    a=k32.GetProcAddress(hk,nm.encode())
    if a: HOOKS[a]=nm; KIND[a]=kind
for nm,kind in (("NtQuerySystemTime","li"),("RtlGetSystemTimePrecise","ret_li")):
    a=k32.GetProcAddress(hntdll,nm.encode())
    if a: HOOKS[a]=nm; KIND[a]=kind
print("hooks:",{hex(k):v for k,v in HOOKS.items()},flush=True)

# pipes for stdin/stdout
class SA(C.Structure): _fields_=[("nLength",W.DWORD),("lpSD",C.c_void_p),("bInherit",W.BOOL)]
sa=SA(C.sizeof(SA),None,True)
o_r=W.HANDLE(); o_w=W.HANDLE(); i_r=W.HANDLE(); i_w=W.HANDLE()
k32.CreatePipe(C.byref(o_r),C.byref(o_w),C.byref(sa),0)
k32.CreatePipe(C.byref(i_r),C.byref(i_w),C.byref(sa),0)
HANDLE_FLAG_INHERIT=1
k32.SetHandleInformation(o_r,HANDLE_FLAG_INHERIT,0)
k32.SetHandleInformation(i_w,HANDLE_FLAG_INHERIT,0)

si=STARTUPINFO(); si.cb=C.sizeof(si); si.dwFlags=STARTF_USESTDHANDLES
si.hStdInput=i_r; si.hStdOutput=o_w; si.hStdError=o_w
pi=PROCESS_INFORMATION()
ok=k32.CreateProcessW(EXE,None,None,None,True,DEBUG_ONLY_THIS_PROCESS,None,None,C.byref(si),C.byref(pi))
if not ok:
    print("CreateProcess failed",C.get_last_error());sys.exit(1)
# feed ENTER presses
k32.WriteFile(i_w,b"\r\n\r\n\r\n\r\n",8,C.byref(W.DWORD()),None)

out=bytearray()
def reader():
    buf=(C.c_char*4096)()
    n=W.DWORD()
    while True:
        if not k32.ReadFile(o_r,buf,4096,C.byref(n),None) or n.value==0: break
        out.extend(buf.raw[:n.value])
th=threading.Thread(target=reader,daemon=True); th.start()

# install int3 at each hook
orig={}
def wpm(addr,data):
    return k32.WriteProcessMemory(pi.hProcess,C.c_void_p(addr),data,len(data),C.byref(C.c_size_t()))
def rpm(addr,n):
    b=(C.c_char*n)(); r=C.c_size_t()
    k32.ReadProcessMemory(pi.hProcess,C.c_void_p(addr),b,n,C.byref(r)); return b.raw[:r.value]
installed=False
de=DEBUG_EVENT()
ftbytes=TARGET_FT.to_bytes(8,'little')
import datetime
print("target FILETIME",TARGET_FT,flush=True)
count=0
while True:
    if not k32.WaitForDebugEvent(C.byref(de),20000):
        print("no debug event (timeout)",flush=True); break
    code=de.dwDebugEventCode
    status=DBG_CONTINUE
    if code==1:
        sys.stderr.write('EVT exc ec=%x addr=%x\n'%(de.u.Exception.ExceptionRecord.ExceptionCode, de.u.Exception.ExceptionRecord.ExceptionAddress or 0))
    else:
        sys.stderr.write('EVT code=%d\n'%code)
    if code==1: # EXCEPTION
        er=de.u.Exception.ExceptionRecord
        ec=er.ExceptionCode
        if ec==EXCEPTION_BREAKPOINT:
            addr=er.ExceptionAddress
            if not installed:
                # first bp = system; now install hooks
                for a in HOOKS:
                    orig[a]=rpm(a,1)
                    wpm(a,b"\xCC")
                installed=True
            elif addr in HOOKS:
                ctx=CONTEXT(); ctx.ContextFlags=CFLAGS
                k32.GetThreadContext(pi.hThread,C.byref(ctx))
                kind=KIND[addr]
                if kind=="ft":
                    wpm(ctx.Rcx,ftbytes)
                elif kind=="li":
                    wpm(ctx.Rcx,ftbytes)
                elif kind=="ret_li":
                    ctx.Rax=TARGET_FT
                elif kind=="st":
                    import struct as _s
                    stb=_s.pack('<8H',2038,1,2,19,3,14,7,0)
                    wpm(ctx.Rcx,stb)
                ret=int.from_bytes(rpm(ctx.Rsp,8),'little')
                ctx.Rip=ret; ctx.Rsp=ctx.Rsp+8
                k32.SetThreadContext(pi.hThread,C.byref(ctx))
                sys.stderr.write("HOOKHIT %s ret=%x rcx=%x\n"%(HOOKS[addr],ret,outptr if False else ctx.Rcx))
                count+=1
            else:
                print("BP at",hex(addr or 0),flush=True)
                status=DBG_EXCEPTION_NOT_HANDLED
        else:
            if de.u.Exception.dwFirstChance:
                pass
            status=DBG_EXCEPTION_NOT_HANDLED
    elif code==5: # EXIT_PROCESS
        print("process exited",flush=True)
        k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,DBG_CONTINUE)
        break
    k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,status)

time.sleep(1.0)
k32.CloseHandle(o_w)
th.join(timeout=2)
print("=== hook hits:",count,"===",flush=True)
print("=== OUTPUT ===",flush=True)
sys.stdout.write(out.decode('latin1'))
