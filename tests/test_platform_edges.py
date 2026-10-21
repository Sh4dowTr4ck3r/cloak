"""Non-Windows file and process edge cases, restricted to ordinary utilities."""
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import benchmark
BIN = None


def setUpModule():
    global BIN
    BIN = benchmark.build_rust('dev')


@unittest.skipUnless(os.name == 'posix', 'Unix platform checks')
class PlatformEdges(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([str(BIN), *map(str, args)], capture_output=True, timeout=15)

    def test_copy_preserves_mode_and_modification_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'sample.txt'
            source.write_bytes(b'hello')
            source.chmod(0o640)
            os.utime(source, ns=(1_000_000_000_123_000_000, 1_000_000_000_456_000_000))
            original = source.stat()
            result = self.run_cli('util', '-c', source, '-n', 'bak', '-q')
            self.assertEqual(result.returncode, 0, result.stderr)
            destination = source.with_suffix('.bak')
            self.assertEqual(destination.stat().st_mtime_ns, original.st_mtime_ns)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o640)
            self.assertEqual(destination.read_bytes(), b'hello')

    def test_same_filesystem_move_preserves_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'target'
            target.write_bytes(b'hello')
            source = Path(tmp) / 'link'
            source.symlink_to('target')
            output = Path(tmp) / 'moved'
            result = self.run_cli('util', '-c', source, '-o', output, '-q')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(output.is_symlink())
            self.assertEqual(os.readlink(output), 'target')
            self.assertFalse(source.is_symlink())
            self.assertEqual(target.read_bytes(), b'hello')

    @unittest.skipIf(hasattr(os, 'geteuid') and os.geteuid() == 0, 'Root bypasses directory permissions')
    def test_permission_failure_preserves_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'input'
            source.write_bytes(b'hello')
            output = Path(tmp) / 'readonly'
            output.mkdir()
            output.chmod(0o500)
            try:
                result = self.run_cli('util', '-c', source, '-o', output / 'out', '-q')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(source.read_bytes(), b'hello')
                self.assertFalse((output / 'out').exists())
            finally:
                output.chmod(0o700)

    def test_cross_filesystem_move_when_available(self):
        with tempfile.TemporaryDirectory() as tmp:
            alternate = Path('/dev/shm')
            if (not alternate.is_dir() or not os.access(alternate, os.W_OK)
                    or alternate.stat().st_dev == Path(tmp).stat().st_dev):
                self.skipTest('No writable second filesystem available')
            with tempfile.TemporaryDirectory(dir=alternate) as other:
                source = Path(tmp) / 'input'
                source.write_bytes(b'hello')
                os.utime(source, (1_000_000_000, 1_000_000_000))
                output = Path(other) / 'output'
                result = self.run_cli('util', '-c', source, '-o', output, '-q')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(output.read_bytes(), b'hello')
                self.assertEqual(int(output.stat().st_mtime), 1_000_000_000)
                self.assertFalse(source.exists())

    def test_ctrl_c_at_prompt_matches_python(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'input'
            source.write_bytes(b'hello')
            for command in ([sys.executable, str(ROOT / 'cloak.py')], [str(BIN)]):
                with self.subTest(command=command):
                    process = subprocess.Popen(command + ['util', '-c', str(source), '-e', '-q'],
                                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                               stderr=subprocess.PIPE)
                    try:
                        with selectors.DefaultSelector() as selector:
                            selector.register(process.stdout, selectors.EVENT_READ)
                            seen = b''
                            deadline = time.monotonic() + 10
                            while b'Select technique' not in seen:
                                remaining = deadline - time.monotonic()
                                self.assertGreater(remaining, 0, 'Timed out waiting for prompt')
                                self.assertTrue(selector.select(remaining), 'No prompt received')
                                chunk = os.read(process.stdout.fileno(), 4096)
                                self.assertTrue(chunk, 'Process exited before prompting')
                                seen += chunk
                        process.send_signal(signal.SIGINT)
                        # Keep stdin open until the signal handler exits; communicate()
                        # would otherwise introduce a competing EOF event.
                        process.wait(timeout=10)
                        stdout, stderr = process.communicate(timeout=10)
                        self.assertEqual(process.returncode, 0, stderr)
                        self.assertIn(b'Interrupted.', seen + stdout)
                        self.assertEqual(source.read_bytes(), b'hello')
                        self.assertFalse(Path(str(source) + '.enc').exists())
                    finally:
                        if process.poll() is None:
                            process.kill()
                            process.communicate()
                        process.stdout.close()
                        process.stderr.close()
                        if not process.stdin.closed:
                            process.stdin.close()
