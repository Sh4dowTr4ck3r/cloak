import base64
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import benchmark
BIN = None

def setUpModule():
    global BIN
    BIN = benchmark.build_rust('dev')

class FinalFixes(unittest.TestCase):
    def cli(self, *args, stdin=''):
        return subprocess.run([str(BIN), *map(str,args)], input=stdin, text=True, capture_output=True, timeout=20)

    def test_hardlinks_preserved(self):
        for flag, destination in [('-n','input.bak'),('-a','input.txt.bak')]:
            with self.subTest(flag=flag), tempfile.TemporaryDirectory() as tmp:
                source=Path(tmp)/'input.txt'; source.write_bytes(b'preserve me')
                dest=Path(tmp)/destination; os.link(source,dest)
                result=self.cli('util','-c',source,flag,'bak','-q')
                self.assertNotEqual(result.returncode,0)
                self.assertEqual(source.read_bytes(),b'preserve me')
                self.assertEqual(dest.read_bytes(),b'preserve me')

    def test_empty_key_rejected(self):
        for key in ['', ' ', '0x', '0X']:
            with self.subTest(key=key),tempfile.TemporaryDirectory() as tmp:
                source=Path(tmp)/'input';source.write_bytes(b'hello')
                result=self.cli('util','-c',source,'-e','--technique','7','--key',key,'-q')
                self.assertNotEqual(result.returncode,0)
                self.assertIn('must not be empty',result.stderr)
                self.assertEqual(list(Path(tmp).iterdir()),[source])

    def test_missing_parent_matches_python(self):
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'input';source.write_bytes(b'hello')
            result=self.cli('util','-c',source,'-e','--technique','1','-o',Path(tmp)/'missing'/'out','-q')
            self.assertNotEqual(result.returncode,0)
            self.assertFalse((Path(tmp)/'missing').exists())
            self.assertEqual(source.read_bytes(),b'hello')

    def test_decoder_parity(self):
        rng=random.Random(42)
        b64_cases=[b'',b'aG!VsbG8=',b'Zg==junk',b'Zh==',b'====',b'AA=A',b'A===',b'AA==',b'AAA=',b'AAAA====',b'AA',b'AAA']
        b64_cases += [bytes(rng.choice(b'ABCabc019+/=! \n\xff') for _ in range(rng.randrange(20))) for _ in range(160)]
        hex_cases=[b'',b'6 8',b'68 65',b'6\t8',b'68\x0b65',b'6',b'GG',b'\xc2\xa068\xc2\xa0',b'\xff']
        for technique,cases,decode in [(1,b64_cases,base64.b64decode),(2,hex_cases,lambda b:bytes.fromhex(b.decode().strip()))]:
            with tempfile.TemporaryDirectory() as tmp:
                source=Path(tmp)/'input'
                for data in cases:
                    with self.subTest(technique=technique,data=data):
                        source.write_bytes(data)
                        try: expected=decode(data); succeeds=True
                        except (ValueError,UnicodeError): succeeds=False
                        result=self.cli('util','-c',source,'-d','--technique',technique,'-q')
                        self.assertEqual(result.returncode==0,succeeds,result.stderr)
                        if succeeds:self.assertEqual(Path(str(source)+'.dec').read_bytes(),expected)

    def test_cargo_artifact_and_output_validation(self):
        benchmark.RUST_BIN=BIN
        self.assertEqual(len(benchmark.verify_ordinary_outputs(bytes(range(256)))),5)
        for iterations in [1,2,4]:
            result=benchmark.bench_python_algo('hex-encode',b'hello',iterations)
            self.assertEqual(result['iterations'],iterations)
            self.assertLessEqual(result['min_ns'],result['median_ns'])
            self.assertLessEqual(result['median_ns'],result['max_ns'])

    def test_prompt_eof_preserves_source(self):
        for flag in ['-e', '-d']:
            with self.subTest(flag=flag), tempfile.TemporaryDirectory() as tmp:
                source=Path(tmp)/'input'; source.write_bytes(b'hello')
                output=Path(tmp)/'out'
                result=self.cli('util','-c',source,flag,'-o',output,'-q')
                self.assertNotEqual(result.returncode,0)
                self.assertIn('EOF',result.stderr)
                self.assertEqual(source.read_bytes(),b'hello')
                self.assertFalse(output.exists())

    def test_common_argument_exit_codes_match_python(self):
        for args in [[], ['info'], ['util'], ['INFO'], ['unknown']]:
            with self.subTest(args=args):
                python=subprocess.run([sys.executable,str(ROOT/'cloak.py'),*args],capture_output=True)
                rust=self.cli(*args)
                self.assertEqual(rust.returncode,python.returncode)
                self.assertEqual(rust.returncode,2)

    def test_info_stdout_matches_python(self):
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'input';source.write_bytes(b'hello')
            args=['info','-c',str(source),'-H','-q']
            python=subprocess.run([sys.executable,str(ROOT/'cloak.py'),*args],capture_output=True,text=True,check=True)
            rust=self.cli(*args)
            self.assertEqual(rust.stdout,python.stdout)
