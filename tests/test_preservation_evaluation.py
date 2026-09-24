"""T06 media preservation and truthful reporting regressions."""
from dataclasses import replace

import pytest

from app.gui.protect_tab import ProtectTab
from app.stego import video_stego
from app.stego.errors import DecodeError
from scripts.evaluate_preservation import evaluate


@pytest.fixture(scope="module")
def evaluation(tmp_path_factory):
    directory = tmp_path_factory.mktemp("preservation") / "run"
    return directory, evaluate(directory)


def test_saved_media_properties_and_size_exceptions(evaluation):
    _, report = evaluation
    assert len(report["cases"]) == 66
    for row in report["cases"]:
        outcome = row["size"]
        assert outcome["final_size"] - outcome["cover_size"] == outcome["difference"]
        assert row["manifest_bytes"] > 0
        if row["cover"] in ("photo_gap.bmp", "tone_metadata.wav"):
            assert not outcome["exact"] and not outcome["inherent"]
            assert "metadata" in outcome["strategy"]
        if row["cover"] == "flat.png" and row["matching_requested"]:
            assert not outcome["exact"] and outcome["content_unchanged"]
        if row["cover"] == "flat_uncompressed.png" and row["matching_requested"]:
            assert outcome["exact"] and outcome["content_unchanged"]


@pytest.mark.parametrize("rate", [0, -1, float("nan"), float("inf")])
def test_unknown_video_timing_is_rejected(evaluation, monkeypatch, rate):
    directory, _ = evaluation
    cover = directory / "video_FFV1_10.000.mkv"
    original = video_stego.media_utils.read_video_properties(cover)
    monkeypatch.setattr(video_stego.media_utils, "read_video_properties",
                        lambda _: replace(original, frame_rate=rate))
    with pytest.raises(DecodeError, match="frame rate"):
        video_stego.describe_only(cover)


def test_odd_video_dimensions_are_rejected(evaluation, monkeypatch):
    directory, _ = evaluation
    cover = directory / "video_FFV1_10.000.mkv"
    original = video_stego.media_utils.read_video_properties(cover)
    monkeypatch.setattr(video_stego.media_utils, "read_video_properties",
                        lambda _: replace(original, width=255))
    with pytest.raises(DecodeError, match="dimensions must be even"):
        video_stego.describe_only(cover)


def test_encoder_timing_change_is_rejected(evaluation, monkeypatch, tmp_path):
    directory, _ = evaluation
    cover = directory / "video_FFV1_10.000.mkv"
    original = video_stego._open_writer
    monkeypatch.setattr(video_stego, "_open_writer",
                        lambda path, descriptor, codec: original(
                            path, replace(descriptor, frame_rate=20), codec))
    target = tmp_path / "changed.mkv"
    with pytest.raises(DecodeError, match="changed the frame rate"):
        video_stego.embed_video(str(cover), str(target), b"timing check", 1, 0)
    assert not target.exists()


@pytest.mark.parametrize("stage", ["input", "output"])
def test_variable_timestamps_are_rejected(evaluation, monkeypatch, tmp_path, stage):
    import cv2

    directory, _ = evaluation
    cover = directory / "video_FFV1_10.000.mkv"
    target = tmp_path / "variable.mkv"
    changed_path = cover if stage == "input" else target
    original = cv2.VideoCapture

    class VariableTimingCapture:
        def __init__(self, path):
            self.capture = original(path)
            self.change = str(path) == str(changed_path)

        def __getattr__(self, name):
            return getattr(self.capture, name)

        def get(self, prop):
            value = self.capture.get(prop)
            return value + 20 if self.change and prop == cv2.CAP_PROP_POS_MSEC and value > 0 else value

    monkeypatch.setattr(cv2, "VideoCapture", VariableTimingCapture)
    with pytest.raises(DecodeError, match="variable-rate"):
        video_stego.embed_video(str(cover), str(target), b"timing", 1, 0)
    assert not target.exists()


def test_saved_video_truncation_is_rejected(evaluation, monkeypatch, tmp_path):
    directory, _ = evaluation
    cover = directory / "video_FFV1_10.000.mkv"
    target = tmp_path / "truncated.mkv"
    original = video_stego.iterate_frames

    def truncated(path, descriptor=None):
        for index, frame in enumerate(original(path, descriptor)):
            if str(path) == str(target) and index == 11:
                break
            yield frame

    monkeypatch.setattr(video_stego, "iterate_frames", truncated)
    with pytest.raises(DecodeError, match="different frame count"):
        video_stego.embed_video(str(cover), str(target), b"count check", 1, 0)
    assert not target.exists()


def test_gui_reports_change_and_separate_manifest(evaluation, qtbot):
    from types import SimpleNamespace

    directory, report = evaluation
    row = next(c for c in report["cases"] if c["cover"] == "tone_metadata.wav")
    tab = ProtectTab()
    qtbot.addWidget(tab)
    tab._cover_path = str(directory / row["cover"])
    target = directory / row["size"]["stego"]
    tab._show_quality(SimpleNamespace(stego_path=str(target),
                                     manifest_path=str(target) + ".manifest.json",
                                     record=SimpleNamespace(lsb_depth=1), size_preservation=None))
    assert "-136 B" in tab.quality_panel.value_for("Size change")
    assert "separate from media" in tab.quality_panel.value_for("Companion manifest")
