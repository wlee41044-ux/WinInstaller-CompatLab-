#!/usr/bin/env python3
"""Read static PE imports without loading or running any executable.

No dependencies; no file contents, game strings, or machine-specific paths are
included in JSON output. Delay-load and dynamic GetProcAddress are reported as
coverage limitations, not silently counted as supported.
"""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import struct
import sys


class InvalidPE(ValueError):
    pass


def u16(b, at):
    if at < 0 or at + 2 > len(b): raise InvalidPE('truncated PE field')
    return struct.unpack_from('<H', b, at)[0]


def u32(b, at):
    if at < 0 or at + 4 > len(b): raise InvalidPE('truncated PE field')
    return struct.unpack_from('<I', b, at)[0]


def u64(b, at):
    if at < 0 or at + 8 > len(b): raise InvalidPE('truncated PE field')
    return struct.unpack_from('<Q', b, at)[0]


def textz(b, at, maxlen=256):
    if at < 0 or at >= len(b): raise InvalidPE('string outside image')
    end=b.find(b'\0', at, min(at+maxlen,len(b)))
    if end < 0: raise InvalidPE('unterminated PE import string')
    try: return b[at:end].decode('ascii')
    except UnicodeDecodeError as exc: raise InvalidPE('non-ASCII import name') from exc


def scan(data: bytes) -> dict:
    if len(data) > 256*1024*1024: raise InvalidPE('PE exceeds offline scanner size limit')
    if len(data) < 0x40 or data[:2] != b'MZ': raise InvalidPE('not an MZ image')
    pe = u32(data,0x3C)
    if pe + 24 > len(data) or data[pe:pe+4]!=b'PE\0\0': raise InvalidPE('not a PE image')
    sections = u16(data,pe+6)
    if sections > 96: raise InvalidPE('excessive sections')
    optsize=u16(data,pe+20)
    opt=pe+24
    if opt+optsize>len(data): raise InvalidPE('truncated optional header')
    magic=u16(data,opt)
    if magic==0x20B:
        width=8; directory=opt+112; count_offset=opt+108
    elif magic==0x10B:
        width=4; directory=opt+96; count_offset=opt+92
    else: raise InvalidPE('unsupported optional header')
    if count_offset+4>opt+optsize: raise InvalidPE('missing data-directory count')
    n=u32(data,count_offset)
    if n<2 or directory+16>opt+optsize:
        return {'arch':'x64' if width==8 else 'x86','imports':[], 'delay_imports_present':False}
    import_rva=u32(data,directory+8)
    delay= bool(n>13 and directory+14*8<=opt+optsize and u32(data,directory+13*8)!=0)
    offset=opt+optsize
    table=[]
    for i in range(sections):
        s=offset+i*40
        if s+40>len(data): raise InvalidPE('truncated section table')
        size=u32(data,s+16); raw=u32(data,s+20); rva=u32(data,s+12); virtual=u32(data,s+8)
        table.append((rva,max(size,virtual),raw,size))

    def rva_offset(rva, required=1):
        for start, span, base, rawsize in table:
            if rva>=start and rva-start+required<=rawsize and rva-start+required<=span:
                at=base+rva-start
                if at+required>len(data): raise InvalidPE('section bytes truncated')
                return at
        raise InvalidPE('RVA outside raw PE sections')

    if not import_rva:return {'arch':'x64' if width==8 else 'x86','imports':[], 'delay_imports_present':delay}
    entries=[]
    for i in range(4096):
        d=rva_offset(import_rva+i*20,20)
        oft=u32(data,d); name_rva=u32(data,d+12); ft=u32(data,d+16)
        if oft==0 and name_rva==0 and ft==0: break
        if name_rva==0: raise InvalidPE('import name RVA missing')
        dll=textz(data,rva_offset(name_rva))
        thunk=oft or ft
        if not thunk:raise InvalidPE('import thunk missing')
        for k in range(65536):
            at=rva_offset(thunk+k*width,width)
            addr=u64(data,at) if width==8 else u32(data,at)
            if addr==0:break
            ordinal_flag=1 << (width*8-1)
            if addr&ordinal_flag:
                symbol=f'#{addr&0xFFFF}'
            else:
                hint_at=rva_offset(addr,3)
                symbol=textz(data,hint_at+2)
            entries.append({'dll':dll,'symbol':symbol})
        else:raise InvalidPE('import thunk table too long')
    else:raise InvalidPE('import descriptor table too long')
    unique={(e['dll'].casefold(),e['symbol']):e for e in entries}
    return {'arch':'x64' if width==8 else 'x86','imports':sorted(unique.values(),key=lambda e:(e['dll'].casefold(),e['symbol'])),'delay_imports_present':delay}


def coverage(scans, manifest):
    known={dll.casefold():set(names) for dll,names in manifest.items()}
    missing=defaultdict(set)
    supported=defaultdict(set)
    for idx,scan_result in enumerate(scans):
        for item in scan_result['imports']:
            key=(item['dll'].casefold(),item['symbol'])
            dest=supported if item['symbol'] in known.get(key[0],set()) else missing
            dest[key].add(idx)
    def report(items):
        return [{'dll':dll,'symbol':symbol,'exe_count':len(exes)} for (dll,symbol),exes in sorted(items.items(),key=lambda x:(-len(x[1]),x[0]))]
    return {'files_scanned':len(scans),'supported':report(supported),'missing':report(missing),
            'limitations':['Only static regular imports are analyzed; delay-load imports are flagged but not enumerated.',
                           'Dynamic LoadLibrary/GetProcAddress calls and runtime behavior are not inferred.',
                           'A symbol present in a manifest does not prove correct semantics.']}


def main(argv=None):
    parser=argparse.ArgumentParser(description='Static PE import coverage audit (no EXE execution)')
    parser.add_argument('exe',nargs='+',type=Path)
    parser.add_argument('--manifest',type=Path,help='JSON object mapping DLL names to supported API lists')
    args=parser.parse_args(argv)
    manifest={}
    if args.manifest:
        manifest=json.loads(args.manifest.read_text(encoding='utf-8'))
        if not isinstance(manifest,dict) or any(not isinstance(k,str) or not isinstance(v,list) or any(not isinstance(t,str) for t in v) for k,v in manifest.items()):
            parser.error('manifest must be a DLL -> API name list dictionary')
    results=[]
    for f in args.exe:
        try:results.append(scan(f.read_bytes()))
        except (InvalidPE,OSError) as exc:parser.error(f'PE parse failed: {type(exc).__name__}: {exc}')
    print(json.dumps({'architectures':[r['arch'] for r in results],
                      'delayed_import_files':sum(r['delay_imports_present'] for r in results),
                      **coverage(results,manifest)},indent=2,ensure_ascii=False))


if __name__=='__main__':
    main()
