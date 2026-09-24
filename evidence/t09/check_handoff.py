"""Validate local links and case references in the T09 handoff documents."""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCUMENTS = [
    "README.md", "AGENTS.md", "docs/IMPLEMENTATION_PLAN.md", "docs/demo_plan.md",
    "docs/evidence_index.md", "docs/submission_handoff.md",
    "docs/contribution_statement.md", "docs/ethics_and_ai_use.md",
    "docs/sample_bundle.md", "docs/challenge_workflows.md", "evidence/t09/README.md",
]


def main():
    links = 0
    for name in DOCUMENTS:
        path = ROOT / name
        for target in re.findall(r"\]\(([^)]+)\)", path.read_text(encoding="utf-8")):
            if "://" in target or target.startswith("#"):
                continue
            target = target.split("#", 1)[0]
            assert (path.parent / target).exists(), (name, target)
            links += 1
    receiver = ROOT / "samples/t07/party-b"
    index = json.loads((receiver / "case-index.json").read_text())
    for case in index["cases"]:
        for field in ("media", "manifest", "public_key"):
            assert (receiver / case[field]).is_file(), (case["id"], field)
    ids = {case["id"] for case in index["cases"]}
    needed = {
        "image-short", "audio-long", "image-file", "audio-file", "image-confidential",
        "image-payload-corruption", "audio-signature-corruption", "video-positive",
        "audio-repetition1-damage1", "audio-repetition3-damage1",
        "audio-repetition3-damage2", "analysis-even-0",
    }
    assert needed <= ids
    print(json.dumps({"local_links_checked": links, "indexed_cases": len(ids),
                      "demo_cases_present": len(needed), "sha256": {
                          name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                          for name in DOCUMENTS}}, indent=2))


if __name__ == "__main__":
    main()
