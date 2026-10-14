"""Synthetic x86 and x64 PE import fixtures, written in memory only."""
import unittest
import struct
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from pe_imports import scan, coverage, InvalidPE


def pe_sample(width=8, symbols=('CreateFileW','DeleteFileW','MissingApi')):
    data=bytearray(0x800)
    data[:2]=b'MZ'
    struct.pack_into('<I',data,0x3c,0x80)
    data[0x80:0x84]=b'PE\0\0'
    struct.pack_into('<H',data,0x84,0x8664 if width==8 else 0x14c)
    struct.pack_into('<H',data,0x86,1)
    struct.pack_into('<H',data,0x94,240 if width==8 else 224)
    opt=0x98
    struct.pack_into('<H',data,opt,0x20b if width==8 else 0x10b)
    dirpos=opt+(112 if width==8 else 96)
    struct.pack_into('<I',data,opt+(108 if width==8 else 92),16)
    struct.pack_into('<II',data,dirpos+8,0x1020,40)
    sec=opt+(240 if width==8 else 224)
    data[sec:sec+6]=b'.rdata'
    struct.pack_into('<IIII',data,sec+8,0x400,0x1000,0x400,0x200)
    to=lambda rva:rva-0x1000+0x200
    struct.pack_into('<IIIII',data,to(0x1020),0x1080,0,0,0x1060,0x1080)
    data[to(0x1060):to(0x1060)+13]=b'KERNEL32.dll\0'
    for i,name in enumerate(symbols):
        at=0x1120+i*48
        struct.pack_into('<Q' if width==8 else '<I',data,to(0x1080)+i*width,at)
        struct.pack_into('<H',data,to(at),0)
        data[to(at)+2:to(at)+2+len(name)+1]=name.encode()+b'\0'
    return bytes(data)


class PeTests(unittest.TestCase):
    def test_x64(self):
        result=scan(pe_sample())
        self.assertEqual(result['arch'],'x64')
        self.assertEqual({e['symbol'] for e in result['imports']},{'CreateFileW','DeleteFileW','MissingApi'})
        self.assertFalse(result['delay_imports_present'])

    def test_x86(self):
        self.assertEqual(scan(pe_sample(4))['arch'],'x86')

    def test_import_coverage(self):
        files=[scan(pe_sample(symbols=('CreateFileW','MissingApi'))),scan(pe_sample(4,symbols=('MissingApi',)))]
        report=coverage(files,{'kernel32.DLL':['CreateFileW']})
        self.assertEqual(report['files_scanned'],2)
        self.assertEqual(report['missing'][0],{'dll':'kernel32.dll','symbol':'MissingApi','exe_count':2})
        self.assertEqual(report['supported'][0]['symbol'],'CreateFileW')

    def test_ordinal(self):
        b=bytearray(pe_sample())
        struct.pack_into('<Q',b,0x280,0x8000000000000034)
        self.assertIn('#52',{x['symbol'] for x in scan(b)['imports']})

    def test_malformed(self):
        for contents in (b'',b'MZ',b'not PE'):
            with self.assertRaises(InvalidPE):scan(contents)
        b=bytearray(pe_sample());b[0x200+0x60]=0xff
        with self.assertRaises(InvalidPE):scan(b)

if __name__=='__main__':unittest.main()
