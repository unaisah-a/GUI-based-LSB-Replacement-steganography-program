import importlib.metadata
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from packaging.requirements import Requirement

from scripts.collect_release_evidence import (
    collect_release_evidence,
    write_release_evidence,
)
from scripts.finalize_release_evidence import build_validation_summary


ROOT = Path(__file__).resolve().parents[1]
RECEIVER = ROOT / "samples" / "r11" / "receiver"


def test_requirement_pins_match_validated_environment():
    requirements = []
    for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines():
        value = line.strip()
        if value and not value.startswith("#"):
            requirements.append(Requirement(value))
    assert requirements
    for requirement in requirements:
        assert requirement.specifier.contains(
            importlib.metadata.version(requirement.name), prereleases=True
        )


def test_release_evidence_is_portable_complete_and_secret_free(tmp_path):
    report = collect_release_evidence(RECEIVER)
    output = tmp_path / "release.json"
    write_release_evidence(report, output)
    saved = json.loads(output.read_text(encoding="utf-8"))
    text = output.read_text(encoding="utf-8")

    assert saved == report
    assert saved["receiver_bundle"]["all_passed"] is True
    assert saved["receiver_bundle"]["capacity_case_passed"] is True
    assert len(saved["receiver_bundle"]["cases"]) == 10
    assert saved["optional_tool_absence"]["passed"] is True
    assert saved["contains_private_signing_key"] is False
    assert saved["contains_secret_values"] is False
    assert str(ROOT) not in text
    assert "PRIVATE KEY" not in text
    secrets = json.loads(
        (RECEIVER / "demo-only-secrets.json").read_text(encoding="utf-8")
    )
    for value in secrets["start_secrets"].values():
        assert value not in text
    for value in secrets["encryption_keys"].values():
        assert value not in text


def test_main_smoke_mode_launches_and_exits():
    environment = os.environ.copy()
    environment["QT_QPA_PLATFORM"] = "offscreen"
    completed = subprocess.run(
        [sys.executable, "main.py", "--smoke-test"],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_desktop_audit_runs_offscreen_for_automation(tmp_path):
    environment = os.environ.copy()
    environment["QT_QPA_PLATFORM"] = "offscreen"
    screenshots = tmp_path / "screenshots"
    report = tmp_path / "desktop.json"
    completed = subprocess.run(
        [
            sys.executable,
            "scripts/run_desktop_release_check.py",
            "--receiver",
            str(RECEIVER),
            "--screenshots",
            str(screenshots),
            "--output",
            str(report),
            "--allow-offscreen",
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=45,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    document = json.loads(report.read_text(encoding="utf-8"))
    assert document["all_passed"] is True
    assert document["qt_platform"] == "offscreen"
    assert [case["actual_verdict"] for case in document["cases"]] == [
        "AUTHENTIC",
        "AUTHENTIC",
        "SIGNATURE_INVALID",
    ]
    assert len(document["screenshots"]) == 3
    assert all((screenshots / item["file"]).is_file() for item in document["screenshots"])


def test_release_evidence_finalizer_checks_artifacts_and_secret_values(tmp_path):
    evidence = tmp_path / "evidence"
    (evidence / "results").mkdir(parents=True)
    (evidence / "logs").mkdir()
    (evidence / "screenshots").mkdir()
    for relative in (
        "results/r12-release-audit.json",
        "results/r12-desktop-audit.json",
        "logs/r12-clean-install.txt",
        "logs/r12-main-smoke.txt",
    ):
        source = ROOT / "evidence" / relative
        destination = evidence / relative
        shutil.copyfile(source, destination)
    desktop = json.loads(
        (evidence / "results" / "r12-desktop-audit.json").read_text(encoding="utf-8")
    )
    for screenshot in desktop["screenshots"]:
        shutil.copyfile(
            ROOT / "evidence" / "screenshots" / screenshot["file"],
            evidence / "screenshots" / screenshot["file"],
        )
    (evidence / "logs" / "r12-full-suite.txt").write_text(
        "578 passed in 1.23s\n", encoding="utf-8"
    )

    summary = build_validation_summary(
        evidence, RECEIVER, screenshots_visually_reviewed=True
    )
    assert summary["all_passed"] is True
    assert summary["test_suite"]["passed"] == 578
    assert summary["receiver_cases"] == 10
    assert summary["desktop"]["qt_platform"] == "windows"
    assert summary["desktop"]["screenshots_visually_reviewed"] is True
    assert summary["contains_private_key_material"] is False
    assert summary["contains_secret_values"] is False
