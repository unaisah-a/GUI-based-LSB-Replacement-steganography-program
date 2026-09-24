"""Copy only receiver data and runtime code, then verify in a new isolated Python process.

Run from the repository root: python evidence/t07/check_isolated_receiver.py --output tmp/t07-isolated
This is local process/file isolation, not an OS access sandbox or a real transfer.
"""
import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def check(output):
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    shutil.copytree(ROOT / "app", output / "app", ignore=shutil.ignore_patterns("__pycache__"))
    (output / "scripts").mkdir()
    shutil.copy2(ROOT / "scripts/verify_sample_bundle.py", output / "scripts/verify_sample_bundle.py")
    shutil.copytree(ROOT / "samples/t07/party-b", output / "received")
    command = [sys.executable, "-I", str(output / "scripts/verify_sample_bundle.py"),
               str(output / "received"), "--report", str(output / "report.json"),
               "--recovered", str(output / "recovered")]
    result = subprocess.run(command, cwd=output, capture_output=True, text=True, timeout=120, check=True)
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    assert report["passed"]
    assert not (output / "party-a").exists()
    assert not (output / "keys").exists()
    summary = dict(command=command, cwd=str(output), returncode=result.returncode,
                   stdout=result.stdout, stderr=result.stderr,
                   sender_folder_present=False, private_key_files=report["private_key_files"],
                   cases=len(report["cases"]), all_expectations_passed=report["passed"],
                   recovered_files=len(list((output / "recovered").iterdir())),
                   limitation="Local file/process isolation; not OS denial of access or an actual human transfer")
    (output / "isolation.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    check(parser.parse_args().output)
