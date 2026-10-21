"""Run with python3 -m unittest discover -s tests after cargo build."""
import hashlib
import contextlib
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import benchmark

sys.path.insert(0, str(ROOT))
import benchmark
BIN = None


def setUpModule():
    global BIN
    BIN = benchmark.build_rust("dev")


class Regressions(unittest.TestCase):
    def test_existing_binary_still_builds(self):
        with patch.object(benchmark.subprocess, 'run') as run:
            run.return_value.returncode = 0
            run.return_value.stdout = '{"reason":"compiler-artifact","target":{"name":"cloak-rs"},"executable":"/custom/target/cloak-rs"}\n'
            with contextlib.redirect_stdout(io.StringIO()):
                benchmark.ensure_rust_binary()
            self.assertIn('--locked', run.call_args.args[0])
            self.assertEqual(benchmark.RUST_BIN, Path('/custom/target/cloak-rs'))

    def test_zero_iterations(self):
        with self.assertRaises(ValueError):
            benchmark.bench_python_algo('hashes', b'hello', 0)
        for cmd in ([sys.executable, str(ROOT/'benchmark.py'), '--iterations', '0'],
                    [str(BIN), 'bench', '--algo', 'hashes', '--iterations', '0']):
            result = subprocess.run(cmd, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'at least 1', result.stderr)

    def test_info_hashes_match_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'sample.bin'
            for data in (b'', b'hello world', bytes(range(256))*1024):
                path.write_bytes(data)
                result = subprocess.run([str(BIN), 'info', '-c', str(path), '-H', '-q'], capture_output=True, check=True)
                for digest in (hashlib.md5, hashlib.sha1, hashlib.sha256):
                    self.assertIn(digest(data).hexdigest().upper().encode(), result.stdout)

    def test_encoding_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'sample.txt'
            path.write_text('hello')
            Path(str(path)+'.enc').mkdir()
            result = subprocess.run([str(BIN), 'info', '-c', str(path), '-e', '--technique', '1', '-q'], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'Failed to write', result.stderr)

    def test_hidden_file_extension(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'.sample.txt'
            path.write_text('hello')
            subprocess.run([str(BIN), 'util', '-c', str(path), '-n', 'bak', '-q'], check=True, capture_output=True)
            self.assertEqual((Path(tmp)/'.sample.bak').read_text(), 'hello')
            self.assertFalse((Path(tmp)/'.sample.txt.bak').exists())

    def test_cli_commands_use_current_python_and_absolute_script(self):
        # Capture command construction without running security-sensitive scenarios.
        calls = []
        def capture(name, py_cmd, rs_cmd, iters):
            calls.append(py_cmd)
            return {'py_avg_ns': 1, 'rs_avg_ns': 1, 'py_median_ns': 1, 'rs_median_ns': 1, 'speedup': 1}
        with patch.object(benchmark, 'ensure_rust_binary'), patch.object(benchmark, 'generate_test_data', return_value=b'hello'), patch.object(benchmark, 'bench_cli_scenario', side_effect=capture), contextlib.redirect_stdout(io.StringIO()):
            benchmark.run_benchmarks([], 1)
        for cmd in calls:
            self.assertEqual(cmd[0], sys.executable)
            self.assertEqual(Path(cmd[1]), ROOT/'cloak.py')
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)/'sample.txt'
            data.write_text('hello')
            subprocess.run(calls[0][:3]+['-c',str(data),'-q'], cwd=tmp, capture_output=True, check=True)

    def test_powershell_does_not_interpolate_inputs(self):
        source = (ROOT/'cloak-rs/src/ads.rs').read_text()
        self.assertNotIn("-Path '{}'", source)
        self.assertIn('-LiteralPath $env:CLOAK_ADS_CARRIER', source)
        self.assertIn('.env("CLOAK_ADS_STREAM", stream_name)', source)
