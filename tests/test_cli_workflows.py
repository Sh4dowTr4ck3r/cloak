"""End-to-end coverage for ordinary file utilities; uses temporary files only."""
import base64
import os
from pathlib import Path
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
    BIN = benchmark.build_rust("dev")


class CliWorkflows(unittest.TestCase):
    def run_cli(self, *args, stdin=''):
        return subprocess.run([str(BIN), *map(str,args)], input=stdin, capture_output=True, text=True, timeout=15)

    def test_codec_bytes_and_roundtrips(self):
        for technique, encode in [(1,base64.b64encode),(2,lambda d:d.hex().upper().encode()),(4,lambda d:d[::-1])]:
            for data in [b'',b'hello\n',bytes(range(256)),bytes(range(256))*4097]:
                with self.subTest(technique=technique,length=len(data)), tempfile.TemporaryDirectory() as tmp:
                    p=Path(tmp)/'sample ü with spaces.bin'; p.write_bytes(data)
                    enc=Path(tmp)/'nested'/'encoded'; enc.parent.mkdir(); dec=Path(tmp)/'decoded'
                    r=self.run_cli('util','-c',p,'-e','--technique',technique,'-o',enc,'-q')
                    self.assertEqual(r.returncode,0,r.stderr)
                    self.assertEqual(enc.read_bytes(),encode(data))
                    self.assertEqual(p.read_bytes(),data)
                    self.assertFalse(Path(str(p)+'.enc').exists())
                    r=self.run_cli('util','-c',enc,'-d','--technique',technique,'-o',dec,'-q')
                    self.assertEqual(r.returncode,0,r.stderr)
                    self.assertEqual(dec.read_bytes(),data)
                    self.assertEqual(enc.read_bytes(),encode(data))

    def test_interactive_base64(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'input';p.write_bytes(b'hello')
            r=self.run_cli('util','-c',p,'-e','-q',stdin='1\n')
            self.assertEqual(r.returncode,0,r.stderr)
            self.assertEqual(Path(str(p)+'.enc').read_bytes(),b'aGVsbG8=')

    def test_whitespace_and_bad_decoding(self):
        for technique,encoded in [(1,b' aGVs\nbG8=\t'),(2,b' 68 65\n6C6C6F\t')]:
            with self.subTest(technique=technique),tempfile.TemporaryDirectory() as tmp:
                p=Path(tmp)/'input';p.write_bytes(encoded)
                r=self.run_cli('util','-c',p,'-d','--technique',technique,'-q')
                self.assertEqual(r.returncode,0,r.stderr)
                self.assertEqual(Path(str(p)+'.dec').read_bytes(),b'hello')
                p.write_bytes(b'!invalid!')
                r=self.run_cli('util','-c',p,'-d','--technique',technique,'-q')
                self.assertNotEqual(r.returncode,0)
                self.assertEqual(p.read_bytes(),b'!invalid!')

    def test_argument_errors(self):
        for args in [[],['unknown'],['info'],['util'],['info','-c','/nonexistent/cloak-test'],['util','-e','-d'],['bench','--algo','unknown'],['bench','--iterations','0']]:
            with self.subTest(args=args):self.assertNotEqual(self.run_cli(*args).returncode,0)

    def test_extension_chain(self):
        for name,expected in [('archive.tar.gz','archive.txt.bak'),('.archive.tar.gz','.archive.txt.bak')]:
            with self.subTest(name=name),tempfile.TemporaryDirectory() as tmp:
                p=Path(tmp)/name;p.write_bytes(b'hello')
                r=self.run_cli('util','-c',p,'-n','txt','-a','bak','-q')
                self.assertEqual(r.returncode,0,r.stderr)
                self.assertEqual((Path(tmp)/expected).read_bytes(),b'hello')
                self.assertEqual(p.read_bytes(),b'hello')

    @unittest.skipIf(os.name=='nt','Checks non-Windows rejection only')
    def test_ads_rejected_off_windows(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'file';p.write_bytes(b'hello')
            for args in [['--ads-list'],['--ads-read','--ads-stream','test','-o',str(Path(tmp)/'out')],['--ads-write',str(p),'--ads-stream','test'],['--ads-delete','--ads-stream','test']]:
                with self.subTest(args=args):
                    r=self.run_cli('util','-c',p,*args,'-q')
                    self.assertNotEqual(r.returncode,0)
                    self.assertIn('requires Windows/NTFS',r.stderr)
                    self.assertEqual(p.read_bytes(),b'hello')

    def test_invalid_technique_preserves_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'input';p.write_bytes(b'hello');out=Path(tmp)/'output'
            r=self.run_cli('util','-c',p,'-e','--technique','99','-o',out,'-q')
            self.assertNotEqual(r.returncode,0,f'Invalid technique succeeded; input exists={p.exists()}, output exists={out.exists()}')
            self.assertEqual(p.read_bytes(),b'hello')

    def test_existing_output_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'input';p.write_bytes(b'hello');out=Path(tmp)/'output';out.mkdir()
            r=self.run_cli('util','-c',p,'-e','--technique','1','-o',out,'-q')
            self.assertEqual(r.returncode,0,r.stderr)
            self.assertEqual((out/'input.enc').read_bytes(),b'aGVsbG8=')

    def test_directory_move_matches_python(self):
        for collision in [False, True]:
            with self.subTest(collision=collision), tempfile.TemporaryDirectory() as tmp:
                outcomes=[]
                for implementation in ['python', 'rust']:
                    folder=Path(tmp)/implementation;folder.mkdir()
                    source=folder/'input';source.write_bytes(b'hello')
                    output=folder/'output';output.mkdir()
                    if collision: (output/'input.enc').write_bytes(b'keep me')
                    args=['util','-c',str(source),'-e','-o',str(output),'-q']
                    if implementation=='python':
                        result=subprocess.run([sys.executable,str(ROOT/'cloak.py'),*args],input='1\n',capture_output=True,text=True,timeout=15)
                    else:
                        result=self.run_cli(*args,'--technique','1')
                    snapshot={str(p.relative_to(folder)):p.read_bytes() for p in folder.rglob('*') if p.is_file()}
                    outcomes.append((result.returncode==0,snapshot))
                self.assertEqual(outcomes[0],outcomes[1])
                self.assertEqual(outcomes[1][0],not collision)

    def test_invalid_technique_range(self):
        for mode in ['-e','-d']:
            for technique in ['0','8','255','-1','abc']:
                with self.subTest(mode=mode,technique=technique),tempfile.TemporaryDirectory() as tmp:
                    source=Path(tmp)/'input';source.write_bytes(b'hello')
                    out=Path(tmp)/'out'
                    result=self.run_cli('util','-c',source,mode,'--technique',technique,'-o',out,'-q')
                    self.assertNotEqual(result.returncode,0)
                    self.assertEqual(source.read_bytes(),b'hello')
                    self.assertEqual(list(Path(tmp).iterdir()),[source])
