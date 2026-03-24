import subprocess, sys, hashlib, zipfile
from pathlib import Path

CLOAK = Path(__file__).parent / "cloak.py"
P     = sys.executable

def run(*args):
    r = subprocess.run([P, str(CLOAK)] + list(args), capture_output=True, text=True, encoding='utf-8', errors='replace')
    return r.returncode, r.stdout + r.stderr

def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()

# setup — zip up something to hide
Path("secret.txt").write_text("this is the hidden secret")
with zipfile.ZipFile("secret.zip", "w") as z:
    z.write("secret.txt")

# embed zip into pic.png
run("embed", "-c", "pic.png", "-p", "secret.zip", "-o", "pic_test.png", "--quiet")

# extract it back out
run("extract", "-c", "pic_test.png", "-o", "recovered.zip", "--quiet")

# verify
orig = sha("secret.zip")
rec  = sha("recovered.zip")
print("[PASS] ZIP recovered intact — hashes match" if orig == rec else f"[FAIL] Hash mismatch\n  orig={orig}\n  rec={rec}")
print("[PASS] pic_test.png exists" if Path("pic_test.png").exists() else "[FAIL] pic_test.png missing")
print("Now open pic_test.png — should look identical to pic.png")

# cleanup
for f in ["secret.txt", "secret.zip", "recovered.zip", "pic_test.png"]:
    Path(f).unlink(missing_ok=True)