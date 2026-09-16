"""Generate exact test fixtures for EICAR and safe PE."""
from pathlib import Path
import shutil

fixtures_dir = Path("tests/fixtures")
fixtures_dir.mkdir(parents=True, exist_ok=True)

# 68-byte standard EICAR string
eicar_bytes = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}"
    + b"$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"
    + b"$H+H*"
)

eicar_file = fixtures_dir / "eicar_test.txt"
with open(eicar_file, "wb") as f:
    f.write(eicar_bytes)

print(f"Written EICAR fixture: {eicar_file} (length: {len(eicar_bytes)})")

# Sample benign PE
sample_pe = fixtures_dir / "sample_benign.exe"
notepad = Path(r"C:\Windows\System32\notepad.exe")
if notepad.is_file() and not sample_pe.is_file():
    shutil.copyfile(notepad, sample_pe)
    print(f"Copied notepad.exe to {sample_pe}")
