"""Check archive bytes, extract a fresh copy and run its isolated receiver/startup."""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--extract", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[2]
    target = args.extract.resolve()
    target.mkdir(parents=True, exist_ok=False)
    hashes = {}
    with zipfile.ZipFile(args.archive) as archive:
        assert archive.testzip() is None
        for name in archive.namelist():
            destination = (target / name).resolve()
            assert destination.is_relative_to(target)
            assert not name.startswith(("samples/r11/", "keys/demo_private/", ".venv", ".git/"))
            data = archive.read(name)
            assert not re.search(rb"(?m)^-----BEGIN [A-Z ]*PRIVATE KEY-----", data)
            assert data == (source / name).read_bytes(), name
            hashes[name] = hashlib.sha256(data).hexdigest()
        assert {".gitattributes", "AGENTS.md", "samples/t07/party-b/sender-public.pem"} <= hashes.keys()
        archive.extractall(target)
    environment = dict(os.environ, QT_QPA_PLATFORM="offscreen")
    environment.pop("PYTHONPATH", None)
    receiver_report = target / "receiver-result.json"
    commands = [
        [sys.executable, "-I", str(target / "scripts/verify_sample_bundle.py"),
         str(target / "samples/t07/party-b"), "--report", str(receiver_report),
         "--recovered", str(target / "recovered")],
        [sys.executable, "-I", str(target / "evidence/t02/probe_baseline.py")],
    ]
    outputs = []
    for command in commands:
        result = subprocess.run(command, cwd=target, env=environment, capture_output=True,
                                text=True, timeout=120, check=True)
        outputs.append({"command": command, "exit_code": result.returncode,
                        "stdout": result.stdout, "stderr": result.stderr})
    receiver = json.loads(receiver_report.read_text(encoding="utf-8"))
    report = {"archive": str(args.archive.resolve()),
              "archive_sha256": hashlib.sha256(args.archive.read_bytes()).hexdigest(),
              "files": len(hashes), "extracted": str(target), "receiver_passed": receiver["passed"],
              "receiver_cases": len(receiver["cases"]), "capacity_checks": len(receiver["capacity_checks"]),
              "recovered_files": len(list((target / "recovered").iterdir())),
              "commands": outputs, "member_sha256": hashes}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with args.report.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps({key: value for key, value in report.items()
                      if key not in {"commands", "member_sha256"}}, indent=2))


if __name__ == "__main__":
    main()
