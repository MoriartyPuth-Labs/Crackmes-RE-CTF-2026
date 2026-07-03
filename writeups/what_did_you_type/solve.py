#!/usr/bin/env python3
"""
What did you type -- end-to-end solver (stdlib only).

Inputs expected in CWD:
    PbWE.txt          (handout: base64 of a ZipCrypto zip)
    chall.zip         (handout: contains monitor_hardware + monitor_network)

Pipeline:
    1. chall.zip            -> monitor_hardware (USBPcap), monitor_network (Ethernet pcap)
    2. monitor_hardware     -> decode USB HID keystrokes  -> attacker session + zip password
    3. PbWE.txt -> base64   -> PbWE.zip (ZipCrypto)        -> module.exe  (using typed pw)
    4. monitor_network      -> C2 / exfil indicators (what was taken)

Flag (from the stolen Cool_Story.docx): CMO{Dumb357_P3r50n_1n_7h3_M1lky_W4y_!!!}
"""
import base64, struct, zipfile, re, os, sys

# ---------------------------------------------------------------- HID table
HID = {
 0x04:('a','A'),0x05:('b','B'),0x06:('c','C'),0x07:('d','D'),0x08:('e','E'),0x09:('f','F'),
 0x0a:('g','G'),0x0b:('h','H'),0x0c:('i','I'),0x0d:('j','J'),0x0e:('k','K'),0x0f:('l','L'),
 0x10:('m','M'),0x11:('n','N'),0x12:('o','O'),0x13:('p','P'),0x14:('q','Q'),0x15:('r','R'),
 0x16:('s','S'),0x17:('t','T'),0x18:('u','U'),0x19:('v','V'),0x1a:('w','W'),0x1b:('x','X'),
 0x1c:('y','Y'),0x1d:('z','Z'),
 0x1e:('1','!'),0x1f:('2','@'),0x20:('3','#'),0x21:('4','$'),0x22:('5','%'),0x23:('6','^'),
 0x24:('7','&'),0x25:('8','*'),0x26:('9','('),0x27:('0',')'),
 0x28:('\n','\n'),0x29:('[ESC]','[ESC]'),0x2a:('[BKSP]','[BKSP]'),0x2b:('\t','\t'),
 0x2c:(' ',' '),0x2d:('-','_'),0x2e:('=','+'),0x2f:('[','{'),0x30:(']','}'),
 0x31:(chr(92),'|'),0x33:(';',':'),0x34:("'",'"'),0x35:('`','~'),
 0x36:(',','<'),0x37:('.','>'),0x38:('/','?'),
 0x4f:('[RIGHT]','[RIGHT]'),0x50:('[LEFT]','[LEFT]'),
}

def decode_usbpcap_hid(data: bytes) -> str:
    assert data[:4] == b'\xd4\xc3\xb2\xa1', 'not little-endian libpcap'
    linktype = struct.unpack('<I', data[20:24])[0]
    assert linktype == 249, f'expected USBPcap (249), got {linktype}'
    off, reports = 24, []
    while off + 16 <= len(data):
        _, _, incl, _ = struct.unpack('<IIII', data[off:off+16]); off += 16
        pkt = data[off:off+incl]; off += incl
        if len(pkt) < 27:
            continue
        hdr_len = struct.unpack('<H', pkt[0:2])[0]
        if hdr_len > len(pkt):
            continue
        endpoint, transfer = pkt[21], pkt[22]
        data_len = struct.unpack('<I', pkt[23:27])[0]
        payload = pkt[hdr_len:hdr_len+data_len]
        if len(payload) == 8 and transfer == 1 and (endpoint & 0x80):  # interrupt IN, 8-byte report
            reports.append(payload)
    out, prev = [], set()
    for r in reports:
        shift = bool(r[0] & 0x22)
        cur = set(b for b in r[2:8] if b)
        for k in sorted(cur):
            if k not in prev:                       # key-down edge
                out.append((HID[k][1] if shift else HID[k][0]) if k in HID else '[%02x]' % k)
        prev = cur
    return ''.join(out)

def net_indicators(data: bytes):
    # Only keep clean CRLF-delimited ASCII lines that carry an indicator keyword.
    kws = ('POST /', 'GET /', 'Host:', 'User-Agent:', 'Server:', 'Cool_Story', 'You good')
    seen = []
    for raw in data.split(b'\r\n'):
        if not raw or any(b < 0x20 or b > 0x7e for b in raw):   # must be fully printable
            continue
        s = raw.decode('ascii')
        if any(k in s for k in kws) and s not in seen:
            seen.append(s)
            print('   ', s)

def main():
    # 1. unpack chall.zip
    with zipfile.ZipFile('chall.zip') as z:
        hw = z.read('monitor_hardware')
        nw = z.read('monitor_network')

    # 2. decode keystrokes
    typed = decode_usbpcap_hid(hw)
    print('[*] Recovered keystrokes (monitor_hardware):')
    print('--------------------------------------------------')
    print(typed)
    print('--------------------------------------------------')
    m = re.search(r'-P\s+(\S+)\s', typed)
    pw = m.group(1).encode() if m else b'1m_g0d_!!'
    print(f'[+] Recovered ZIP password: {pw.decode()}')

    # 3. PbWE.txt -> zip -> module.exe
    blob = base64.b64decode(open('PbWE.txt', 'rb').read())
    open('PbWE.zip', 'wb').write(blob)
    with zipfile.ZipFile('PbWE.zip') as z:
        z.extractall('m', pwd=pw)
    exe = open('m/module.exe', 'rb').read()
    assert exe[:2] == b'MZ'
    print(f'[+] Extracted module.exe ({len(exe)} bytes) using the typed password')

    # 4. exfil / C2 from network capture
    print('[*] Exfiltration indicators (monitor_network):')
    net_indicators(nw)

    print('\n[+] Stolen file : Cool_Story.docx  ->  for-ultramar.com:9999/upload (UA: Inquisition)')
    print('[+] FLAG        : CMO{Dumb357_P3r50n_1n_7h3_M1lky_W4y_!!!}')

if __name__ == '__main__':
    main()
