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
    machine=u16(data,pe+4)
    if (machine,magic) not in ((0x8664,0x20B),(0x14c,0x10B)):
        raise InvalidPE('only matching x86/PE32 and x64/PE32+ images are supported')
    if directory+n*8>opt+optsize:raise InvalidPE('declared data directories exceed optional header')
    offset=opt+optsize
    table=[]
    for i in range(sections):
        s=offset+i*40
        if s+40>len(data): raise InvalidPE('truncated section table')
        size=u32(data,s+16); raw=u32(data,s+20); rva=u32(data,s+12); virtual=u32(data,s+8)
        table.append((rva,max(size,virtual),raw,size))

    if n<2:
        return {'arch':'x64' if width==8 else 'x86','imports':[], 'delay_imports_present':False}
    import_rva=u32(data,directory+8)
    import_size=u32(data,directory+12)
    delay=bool(n>13 and u32(data,directory+13*8)!=0)

    def rva_offset(rva, required=1):
        for start, span, base, rawsize in table:
            if rva>=start and rva-start+required<=rawsize and rva-start+required<=span:
                at=base+rva-start
                if at+required>len(data): raise InvalidPE('section bytes truncated')
                return at
        raise InvalidPE('RVA outside raw PE sections')

    if not import_rva:return {'arch':'x64' if width==8 else 'x86','imports':[], 'delay_imports_present':delay}
    def rva_text(rva):
        # Validate every byte against backed section data, including the terminator.
        out=bytearray()
        for index in range(256):
            char=data[rva_offset(rva+index)]
            if char==0:
                try:return out.decode('ascii')
                except UnicodeDecodeError as exc:raise InvalidPE('non-ASCII import name') from exc
            out.append(char)
        raise InvalidPE('unterminated PE import string')

    entries=[]
    for i in range(4096):
        if i*20+20>import_size:raise InvalidPE('import descriptors exceed directory size')
        d=rva_offset(import_rva+i*20,20)
        oft=u32(data,d); name_rva=u32(data,d+12); ft=u32(data,d+16)
        if data[d:d+20]==b'\0'*20: break
        if name_rva==0: raise InvalidPE('import name RVA missing')
        dll=rva_text(name_rva)
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
                rva_offset(addr,3)
                symbol=rva_text(addr+2)
            entries.append({'dll':dll,'symbol':symbol})
        else:raise InvalidPE('import thunk table too long')
    else:raise InvalidPE('import descriptor table too long')
    unique={(e['dll'].casefold(),e['symbol']):e for e in entries}
    return {'arch':'x64' if width==8 else 'x86','imports':sorted(unique.values(),key=lambda e:(e['dll'].casefold(),e['symbol'])),'delay_imports_present':delay}


STATUSES=('TESTED','PARTIAL','EXPERIMENTAL','UNSUPPORTED')


def manifest_entries(manifest):
    """Normalize legacy declarations or a versioned contract; reject ambiguity."""
    if not isinstance(manifest,dict):raise ValueError('manifest must be an object')
    entries={}
    if 'schema_version' in manifest:
        if manifest['schema_version']!=2 or not isinstance(manifest.get('apis'),list):
            raise ValueError('expected schema_version 2 and apis list')
        for api in manifest['apis']:
            if not isinstance(api,dict) or any(not isinstance(api.get(k),str) or not api[k] for k in ('dll','name','status')):
                raise ValueError('invalid API contract entry')
            key=(api['dll'].casefold(),api['name'])
            if api['status'] not in STATUSES or key in entries:raise ValueError('unknown status or duplicate API')
            entries[key]=api['status']
        return entries,'v2_contract'
    for dll,names in manifest.items():
        if not isinstance(dll,str) or not isinstance(names,list) or any(not isinstance(n,str) for n in names):
            raise ValueError('legacy manifest must map DLL names to API lists')
        for name in names:entries[(dll.casefold(),name)]='EXPERIMENTAL'
    return entries,'legacy_unverified_declarations'


def coverage(scans, manifest):
    known,kind=manifest_entries(manifest)
    buckets={status:defaultdict(set) for status in STATUSES}
    declared=defaultdict(set)
    per_input=[];dynamic=[];delayed=[]
    for idx,result in enumerate(scans):
        counts=Counter()
        symbols={(e['dll'].casefold(),e['symbol']) for e in result['imports']}
        for key in symbols:
            status=known.get(key,'UNSUPPORTED'); buckets[status][key].add(idx);counts[status]+=1
            if key in known and status!='UNSUPPORTED':declared[key].add(idx)
        if any(symbol in ('LoadLibraryA','LoadLibraryW','LoadLibraryExA','LoadLibraryExW','GetProcAddress','LdrGetProcedureAddress') for _,symbol in symbols):dynamic.append(idx)
        if result.get('delay_imports_present'):delayed.append(idx)
        per_input.append({'input_index':idx,'arch':result['arch'],'static_import_count':len(symbols),
                          'counts':{status:counts[status] for status in STATUSES}})
    def report(items):
        return [{'dll':dll,'symbol':symbol,'exe_count':len(exes)} for (dll,symbol),exes in sorted(items.items(),key=lambda x:(-len(x[1]),x[0]))]
    by_status={status:report(items) for status,items in buckets.items()}
    return {'files_scanned':len(scans),
            # Legacy output retained; its declarations are explicitly unverified.
            'supported':report(declared) if kind.startswith('legacy') else by_status['TESTED'],
            'missing':by_status['UNSUPPORTED'],'by_status':by_status,'manifest_kind':kind,
            'per_input':per_input,'dynamic_resolution_inputs':dynamic,'delay_import_inputs':delayed,
            'runtime_verified':False,
            'limitations':['Only static regular imports are analyzed; delay-load imports are flagged but not enumerated.',
                           'Dynamic resolution imports indicate possibility only; target APIs and runtime calls are unknown.',
                           'TESTED describes a declared host API subset, not a successfully executed Windows application.',
                           'Legacy supported output means listed declaration only; use v2 contracts for status-aware results.']}


def main(argv=None):
    parser=argparse.ArgumentParser(description='Static PE import coverage audit (no EXE execution)')
    parser.add_argument('exe',nargs='+',type=Path)
    parser.add_argument('--manifest',type=Path,help='legacy DLL lists or version 2 API contracts JSON')
    args=parser.parse_args(argv)
    manifest={}
    if args.manifest:
        try:
            manifest=json.loads(args.manifest.read_text(encoding='utf-8'))
            manifest_entries(manifest)
        except (ValueError,OSError) as exc:parser.error(f'invalid manifest: {exc}')
    results=[]
    for f in args.exe:
        try:results.append(scan(f.read_bytes()))
        except (InvalidPE,OSError) as exc:parser.error(f'PE parse failed: {type(exc).__name__}: {exc}')
    print(json.dumps({'architectures':[r['arch'] for r in results],
                      'delayed_import_files':sum(r['delay_imports_present'] for r in results),
                      **coverage(results,manifest)},indent=2,ensure_ascii=False))


if __name__=='__main__':
    main()
