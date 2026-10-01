"""Verify a bundle using only copied receiver data and runtime in a fresh process."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def check(bundle: Path, output: Path) -> dict:
    bundle = bundle.resolve()
    output = output.resolve()
    if not (bundle / "case-index.json").is_file():
        raise ValueError("Bundle must be the Party B folder containing case-index.json")
    if output.is_relative_to(bundle):
        raise ValueError("Isolation output must be outside the receiver bundle")
    output.mkdir(parents=True, exist_ok=False)
    shutil.copytree(ROOT / "app", output / "app", ignore=shutil.ignore_patterns("__pycache__"))
    (output / "scripts").mkdir()
    shutil.copy2(ROOT / "scripts/verify_sample_bundle.py", output / "scripts/verify_sample_bundle.py")
    shutil.copytree(bundle, output / "received")
    command = [sys.executable, "-I", str(output / "scripts/verify_sample_bundle.py"),
               str(output / "received"), "--report", str(output / "report.json"),
               "--recovered", str(output / "recovered")]
    result = subprocess.run(command, cwd=output, capture_output=True, text=True,
                            timeout=120, check=True)
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    if not report["passed"] or (output / "party-a").exists():
        raise RuntimeError("Isolated receiver acceptance failed")
    summary = dict(
        command=command, cwd=str(output), returncode=result.returncode,
        stdout=result.stdout, stderr=result.stderr, sender_folder_present=False,
        private_key_files=report["private_key_files"], cases=len(report["cases"]),
        capacity_checks=len(report["capacity_checks"]),
        all_expectations_passed=report["passed"],
        recovered_files=len(list((output / "recovered").iterdir())),
        limitation="Local file/process isolation; not OS denial of access or an actual human transfer",
    )
    (output / "isolation.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(check(args.bundle, args.output), indent=2))


if __name__ == "__main__":
    main()
