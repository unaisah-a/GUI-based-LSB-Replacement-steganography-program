"""Check retained fixture bytes, reduced bundle and current document links."""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    hashes = json.loads((ROOT / "evidence/s01/retained-fixture-hashes.json").read_text())
    for name, expected in hashes.items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == expected, name
    bundle = ROOT / "samples/t07"
    index = json.loads((bundle / "party-b/case-index.json").read_text())
    assert index["schema"] == "t07-v2"
    assert len(index["cases"]) == 18
    assert len(index["capacity_cases"]) == 2
    assert "analysis_pairs" not in index
    assert not list(bundle.rglob("analysis-*"))
    for case in index["cases"]:
        for field in ("media", "manifest", "public_key"):
            assert (bundle / "party-b" / case[field]).is_file()
    for name in ("app/gui/steganalysis_tab.py", "app/analysis/steganalysis.py",
                 "tests/test_steganalysis.py"):
        assert not (ROOT / name).exists(), name
    links = 0
    documents = [ROOT / "README.md", ROOT / "AGENTS.md", ROOT / "evidence/s01/README.md"]
    documents += list((ROOT / "docs").glob("*.md"))
    for path in documents:
        for target in re.findall(r"\]\(([^)]+)\)", path.read_text(encoding="utf-8")):
            if "://" in target or target.startswith("#"):
                continue
            target = target.split("#", 1)[0]
            assert (path.parent / target).exists(), (path.name, target)
            links += 1
    print(json.dumps({"retained_fixture_hashes": len(hashes), "verification_cases": 18,
                      "capacity_checks": 2, "local_links": links, "passed": True}, indent=2))


if __name__ == "__main__":
    main()
