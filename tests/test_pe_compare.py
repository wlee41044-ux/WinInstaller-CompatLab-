"""Only generated in-memory PE files; never loads an executable."""
import contextlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from pe_imports import scan, coverage, main, InvalidPE
from test_pe_imports import pe_sample


def contract():
    return {'schema_version':2,'apis':[
        {'dll':'kernel32.dll','name':'CreateFileW','status':'PARTIAL'},
        {'dll':'kernel32.dll','name':'DeleteFileW','status':'TESTED'},
        {'dll':'kernel32.dll','name':'MissingApi','status':'UNSUPPORTED'},
        {'dll':'kernel32.dll','name':'ExperimentalApi','status':'EXPERIMENTAL'}]}


class CompareTests(unittest.TestCase):
    def test_status_buckets_do_not_claim_partial_or_unsupported_tested(self):
        result=coverage([scan(pe_sample())],contract())
        self.assertEqual([i['symbol'] for i in result['supported']],['DeleteFileW'])
        self.assertEqual(result['by_status']['PARTIAL'][0]['symbol'],'CreateFileW')
        self.assertEqual(result['by_status']['UNSUPPORTED'][0]['symbol'],'MissingApi')
        self.assertEqual(result['missing'][0]['symbol'],'MissingApi')

    def test_frequency_is_per_exe_not_per_duplicate_import(self):
        one={'imports':[{'dll':'KERNEL32.dll','symbol':'MissingApi'}]*3,'arch':'x64','delay_imports_present':False}
        two=scan(pe_sample(4,symbols=('MissingApi',)))
        result=coverage([one,two],contract())
        self.assertEqual(result['missing'][0]['exe_count'],2)
        self.assertEqual(result['per_input'][0]['input_index'],0)
        self.assertEqual(result['per_input'][0]['counts']['UNSUPPORTED'],1)

    def test_legacy_lists_are_unverified_declarations(self):
        result=coverage([scan(pe_sample())],{'kernel32.dll':['CreateFileW']})
        self.assertEqual(result['by_status']['EXPERIMENTAL'][0]['symbol'],'CreateFileW')
        self.assertIn('legacy',result['manifest_kind'])

    def test_invalid_contract_rejected(self):
        for data in (
            {'schema_version':3,'apis':[]},
            {'schema_version':2,'apis':[{'dll':'x','name':'x','status':'SUPPORTED'}]},
            {'schema_version':2,'apis':[{'dll':'x','name':'x','status':'TESTED'}]*2},
            {'x':['ok',3]}, {'x':'not-a-list'}):
            with self.subTest(data=data),self.assertRaises(ValueError):coverage([],data)

    def test_delay_and_dynamic_are_not_runtime_evidence(self):
        b=bytearray(pe_sample(symbols=('LoadLibraryW','GetProcAddress')))
        struct.pack_into('<II',b,0x98+112+13*8,0x1200,32)
        result=coverage([scan(b)],contract())
        self.assertEqual(result['dynamic_resolution_inputs'],[0])
        self.assertEqual(result['delay_import_inputs'],[0])
        self.assertFalse(result['runtime_verified'])

    def test_experimental_import_is_separate(self):
        result=coverage([scan(pe_sample(symbols=('ExperimentalApi',)))],contract())
        self.assertEqual(result['by_status']['EXPERIMENTAL'][0]['symbol'],'ExperimentalApi')
        self.assertEqual(result['supported'],[])

    def test_cli_contract_and_legacy_merge_no_paths_or_contents(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); private=root/'private-user-name.exe'; private.write_bytes(pe_sample())
            manifest=root/'manifest.json'; manifest.write_text(json.dumps(contract()))
            stdout=io.StringIO()
            with contextlib.redirect_stdout(stdout):main(['--manifest',str(manifest),str(private)])
            text=stdout.getvalue(); parsed=json.loads(text)
            self.assertEqual(parsed['architectures'],['x64'])
            self.assertNotIn('private-user-name',text);self.assertNotIn(tmp,text)
            self.assertFalse(parsed['runtime_verified'])

    def test_strings_cannot_read_outside_raw_section(self):
        b=bytearray(pe_sample(symbols=('Only',)))
        struct.pack_into('<I',b,0x220+12,0x13ff)
        b[0x5ff:0x604]=b'X.dll' # null is OUTSIDE declared raw section
        with self.assertRaises(InvalidPE):scan(b)

    def test_import_descriptor_must_terminate_within_directory(self):
        b=bytearray(pe_sample());struct.pack_into('<I',b,0x98+112+12,20)
        with self.assertRaises(InvalidPE):scan(b)

    def test_machine_optional_header_mismatch(self):
        b=bytearray(pe_sample());struct.pack_into('<H',b,0x84,0xaa64)
        with self.assertRaises(InvalidPE):scan(b)

    def test_no_import_paths_still_validate_machine_directories_and_sections(self):
        wrong_machine=bytearray(pe_sample())
        struct.pack_into('<H',wrong_machine,0x84,0xaa64)
        struct.pack_into('<I',wrong_machine,0x98+108,0)
        short_header=bytearray(pe_sample())
        struct.pack_into('<H',short_header,0x94,112)
        missing_sections=bytearray(pe_sample())
        struct.pack_into('<I',missing_sections,0x98+108,0)
        missing_sections=missing_sections[:0x98+240]
        for contents in (wrong_machine,short_header,missing_sections):
            with self.subTest(size=len(contents)),self.assertRaises(InvalidPE):scan(contents)
        for width in (4,8):
            valid=bytearray(pe_sample(width))
            struct.pack_into('<I',valid,0x98+(108 if width==8 else 92),0)
            self.assertEqual(scan(valid)['imports'],[])

    def test_repository_contract_matches_legacy_and_test_evidence(self):
        root=Path(__file__).resolve().parents[1]
        legacy=json.loads((root/'data/lab_manifest.json').read_text())
        data=json.loads((root/'data/api_contracts.json').read_text())
        implemented={(x['dll'].casefold(),x['name']) for x in data['apis'] if x['status']!='UNSUPPORTED'}
        listed={(dll.casefold(),name) for dll,names in legacy.items() for name in names}
        self.assertEqual(implemented,listed)
        for api in data['apis']:
            if api['status']!='UNSUPPORTED':
                self.assertTrue(api['tests'])
                for path in api['tests']:self.assertTrue((root/path).is_file(),path)
                for field in ('encoding','returns','errors','limitations','host_dependencies','supported_flags'):
                    self.assertIn(field,api)

if __name__=='__main__':unittest.main()
