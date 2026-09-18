"""Tests for the video steganography layer, its attacks, and the Video tab.

Real clips throughout. The correctness of this layer is almost entirely about whether
a codec preserves pixels exactly, and a stubbed file cannot test that — so every test
here encodes and decodes actual video. The clips are tiny (32x24 for eight frames) to
keep that affordable.

Two claims get the most attention, because they are the two that would make the
feature useless if they were false:

* a payload survives a lossless round trip through the container, including when it
  crosses frame boundaries, and
* it does *not* survive a lossy re-encode, which is what happens to a clip by default.

The frame-count checks matter more than they look. The sample domain is measured in
frames, so a container that reports a frame count different from what decodes would
make the sender and receiver look in different places, silently. The layer refuses
rather than trusting it, and that refusal is tested.
"""

from __future__ import annotations

import os

import numpy as np
import pytest

from app.analysis import quality_metrics
from app.attacks import registry, video_attacks
from app.crypto import key_manager
from app.crypto.encryption import MIN_SCRYPT_N
from app.stego import media, video_stego
from app.stego.errors import (
    CapacityError,
    DecodeError,
    ExtractionError,
    FileError,
    ValidationError,
)
from app.utils import constants
from app.verification import media_compare, verdicts
from app.verification.protect import protect_media
from app.verification.verifier import verify_media

from conftest import make_video_frames, write_video_file

PAYLOAD = b"A payload carried by a video clip."
START_SECRET = "the start secret"
FAST_SCRYPT = {"scrypt_n": MIN_SCRYPT_N, "scrypt_r": 8, "scrypt_p": 1}


@pytest.fixture(scope="module")
def keys():
    return key_manager.generate_key_pair(constants.RSA_MIN_KEY_SIZE)


@pytest.fixture()
def cover(video_factory):
    return video_factory()


@pytest.fixture()
def big_cover(video_factory):
    """Big enough for a signed envelope at a modest depth, and for a region past it."""
    return video_factory(frame_count=12, height=48, width=64, name="big")


# --------------------------------------------------------------------------- #
# Reading and describing
# --------------------------------------------------------------------------- #


class TestDescribe:
    def test_the_descriptor_reports_the_flat_sample_domain(self, cover):
        descriptor = video_stego.describe_only(cover)

        assert descriptor.frame_count == 8
        assert (descriptor.width, descriptor.height) == (32, 24)
        assert descriptor.channel_count == 3
        assert descriptor.samples_per_frame == 24 * 32 * 3
        assert descriptor.total_samples == 8 * 24 * 32 * 3

    def test_the_container_and_codec_are_reported(self, cover):
        descriptor = video_stego.describe_only(cover)

        assert descriptor.container_format == constants.CONTAINER_MKV
        assert descriptor.codec.lower() == "ffv1"

    def test_a_missing_file_is_refused(self, tmp_path):
        with pytest.raises(FileError, match="not found"):
            video_stego.describe_only(str(tmp_path / "absent.mkv"))

    def test_a_container_with_no_stream_is_refused(self, tmp_path):
        """An EBML header is a container, not a clip."""
        path = tmp_path / "empty.mkv"
        path.write_bytes(b"\x1a\x45\xdf\xa3" + b"\x00" * 128)

        with pytest.raises(DecodeError):
            video_stego.describe_only(str(path))

    def test_frames_are_yielded_in_order_and_are_distinct(self, cover):
        frames = list(video_stego.iterate_frames(cover))
        expected = make_video_frames()

        assert len(frames) == len(expected)
        for actual, wanted in zip(frames, expected, strict=True):
            assert np.array_equal(actual, wanted)

    def test_the_generated_frames_really_do_differ(self):
        """Otherwise a frame-ordering bug could pass every test above."""
        frames = make_video_frames(frame_count=3)
        assert not np.array_equal(frames[0], frames[1])
        assert not np.array_equal(frames[1], frames[2])


class TestSampleRange:
    def test_a_range_inside_one_frame_is_read(self, cover):
        descriptor = video_stego.describe_only(cover)
        samples = video_stego.read_sample_range(cover, descriptor, 100, 200)

        expected = make_video_frames()[0].reshape(-1)[100:200]
        assert np.array_equal(samples, expected)

    def test_a_range_spanning_frames_is_read(self, cover):
        descriptor = video_stego.describe_only(cover)
        per_frame = descriptor.samples_per_frame
        begin = per_frame - 50
        end = per_frame + 50

        samples = video_stego.read_sample_range(cover, descriptor, begin, end)
        frames = make_video_frames()
        expected = np.concatenate(
            [frames[0].reshape(-1)[begin:], frames[1].reshape(-1)[:50]]
        )
        assert np.array_equal(samples, expected)

    def test_an_empty_range_is_empty(self, cover):
        descriptor = video_stego.describe_only(cover)
        assert video_stego.read_sample_range(cover, descriptor, 10, 10).size == 0

    def test_a_backwards_range_is_refused(self, cover):
        descriptor = video_stego.describe_only(cover)
        with pytest.raises(ValidationError):
            video_stego.read_sample_range(cover, descriptor, 200, 100)

    def test_a_range_past_the_clip_is_reported_as_truncated(self, cover):
        descriptor = video_stego.describe_only(cover)
        beyond = descriptor.total_samples + 500

        with pytest.raises(ExtractionError, match="truncated"):
            video_stego.read_sample_range(
                cover, descriptor, descriptor.total_samples - 10, beyond
            )


# --------------------------------------------------------------------------- #
# Capacity
# --------------------------------------------------------------------------- #


class TestCapacity:
    def test_capacity_scales_with_depth(self, cover):
        first, _ = video_stego.measure_capacity(cover, 1)
        fourth, _ = video_stego.measure_capacity(cover, 4)

        assert fourth.available_capacity_bytes == first.available_capacity_bytes * 4

    def test_capacity_matches_the_arithmetic(self, cover):
        report, descriptor = video_stego.measure_capacity(cover, 2)
        assert report.total_embeddable_samples == descriptor.total_samples
        assert report.available_capacity_bytes == descriptor.total_samples * 2 // 8

    def test_an_oversized_payload_is_reported_not_raised(self, cover):
        report, _ = video_stego.measure_capacity(cover, 1, 0, 10_000_000)
        assert report.payload_fits is False

    def test_embedding_an_oversized_payload_raises(self, cover, tmp_path):
        with pytest.raises(CapacityError, match="does not fit"):
            video_stego.embed_video(
                cover, str(tmp_path / "out.mkv"), b"x" * 10_000_000, 1, 0
            )


# --------------------------------------------------------------------------- #
# Round trip
# --------------------------------------------------------------------------- #


class TestRoundTrip:
    @pytest.mark.parametrize("depth", [1, 2, 3, 5, 8])
    def test_a_payload_round_trips_at_every_depth(self, cover, tmp_path, depth):
        output = str(tmp_path / f"stego{depth}.mkv")
        result = video_stego.embed_video(cover, output, PAYLOAD, depth, 0)

        assert video_stego.extract_video(result.output_path, depth, 0) == PAYLOAD

    def test_an_empty_payload_round_trips(self, cover, tmp_path):
        result = video_stego.embed_video(cover, str(tmp_path / "s.mkv"), b"", 1, 0)
        assert video_stego.extract_video(result.output_path, 1, 0) == b""

    def test_a_payload_crossing_a_frame_boundary_round_trips(self, cover, tmp_path):
        """The point of the flat domain: nothing special happens at a frame edge."""
        descriptor = video_stego.describe_only(cover)
        # Start 40 samples before the end of frame 0, at depth 1, so the encoded
        # stream necessarily runs into frame 1.
        start = descriptor.samples_per_frame - 40
        payload = bytes(range(64))

        result = video_stego.embed_video(
            cover, str(tmp_path / "crossing.mkv"), payload, 1, start
        )
        assert result.first_frame_touched == 0
        assert result.last_frame_touched >= 1
        assert result.frames_touched >= 2
        assert video_stego.extract_video(result.output_path, 1, start) == payload

    def test_a_payload_spanning_many_frames_round_trips(self, big_cover, tmp_path):
        payload = bytes(range(256)) * 12  # more than two frames' worth at depth 1

        result = video_stego.embed_video(
            big_cover, str(tmp_path / "many.mkv"), payload, 1, 0
        )
        assert result.frames_touched >= 3
        assert video_stego.extract_video(result.output_path, 1, 0) == payload

    def test_the_output_is_always_matroska(self, cover, tmp_path):
        result = video_stego.embed_video(cover, str(tmp_path / "s.mkv"), PAYLOAD, 1, 0)
        assert result.container_format == constants.CONTAINER_MKV
        assert video_stego.describe_only(result.output_path).codec.lower() == "ffv1"

    def test_the_cover_is_left_untouched(self, cover, tmp_path):
        from pathlib import Path

        before = Path(cover).read_bytes()
        video_stego.embed_video(cover, str(tmp_path / "s.mkv"), PAYLOAD, 2, 0)
        assert Path(cover).read_bytes() == before

    def test_frames_outside_the_payload_are_bit_identical(self, cover, tmp_path):
        """The distortion has to be confined to the frames the payload occupies."""
        result = video_stego.embed_video(
            cover, str(tmp_path / "s.mkv"), PAYLOAD, 1, 0
        )
        original = list(video_stego.iterate_frames(cover))
        stego = list(video_stego.iterate_frames(result.output_path))

        for index, (a, b) in enumerate(zip(original, stego, strict=True)):
            if index > result.last_frame_touched:
                assert np.array_equal(a, b), f"frame {index} changed"

    def test_only_the_low_bits_of_touched_frames_changed(self, cover, tmp_path):
        depth = 3
        result = video_stego.embed_video(
            cover, str(tmp_path / "s.mkv"), PAYLOAD, depth, 0
        )
        original = np.concatenate(
            [f.reshape(-1) for f in video_stego.iterate_frames(cover)]
        )
        stego = np.concatenate(
            [f.reshape(-1) for f in video_stego.iterate_frames(result.output_path)]
        )

        keep = np.uint8(0xFF ^ ((1 << depth) - 1))
        assert np.array_equal(original & keep, stego & keep)


class TestExtractionSafety:
    def test_a_wrong_depth_does_not_return_the_payload(self, cover, tmp_path):
        result = video_stego.embed_video(cover, str(tmp_path / "s.mkv"), PAYLOAD, 2, 0)
        try:
            recovered = video_stego.extract_video(result.output_path, 1, 0)
        except ExtractionError:
            return  # the honest outcome
        assert recovered != PAYLOAD

    def test_a_wrong_start_location_does_not_return_the_payload(self, cover, tmp_path):
        result = video_stego.embed_video(cover, str(tmp_path / "s.mkv"), PAYLOAD, 2, 0)
        try:
            recovered = video_stego.extract_video(result.output_path, 2, 999)
        except ExtractionError:
            return
        assert recovered != PAYLOAD

    def test_a_manifest_length_disagreement_is_reported(self, cover, tmp_path):
        result = video_stego.embed_video(cover, str(tmp_path / "s.mkv"), PAYLOAD, 2, 0)
        with pytest.raises(ExtractionError, match="disagrees"):
            video_stego.extract_video(
                result.output_path, 2, 0, manifest_payload_length=len(PAYLOAD) + 1
            )

    def test_a_start_location_past_the_clip_is_refused(self, cover, tmp_path):
        with pytest.raises(ValidationError):
            video_stego.embed_video(
                cover, str(tmp_path / "s.mkv"), PAYLOAD, 1, 10_000_000
            )

    def test_embedding_over_the_input_is_refused(self, cover):
        with pytest.raises(ValidationError, match="differ"):
            video_stego.embed_video(cover, cover, PAYLOAD, 1, 0)

    def test_an_occupied_output_is_refused(self, cover, tmp_path):
        output = tmp_path / "taken.mkv"
        output.write_bytes(b"already here")

        with pytest.raises(FileError, match="occupied"):
            video_stego.embed_video(cover, str(output), PAYLOAD, 1, 0)

    def test_a_non_bytes_payload_is_refused(self, cover, tmp_path):
        with pytest.raises(ValidationError, match="bytes"):
            video_stego.embed_video(cover, str(tmp_path / "s.mkv"), "text", 1, 0)

    def test_a_boolean_start_location_is_refused(self, cover, tmp_path):
        """True meaning index 1 would hide a caller's mistake."""
        with pytest.raises(ValidationError, match="integer"):
            video_stego.embed_video(cover, str(tmp_path / "s.mkv"), PAYLOAD, 1, True)

    def test_a_numpy_integer_start_location_is_accepted(self, cover, tmp_path):
        """A derived start location arrives from numpy arithmetic."""
        result = video_stego.embed_video(
            cover, str(tmp_path / "s.mkv"), PAYLOAD, 1, np.int64(64)
        )
        assert video_stego.extract_video(result.output_path, 1, 64) == PAYLOAD


class TestRoundTripVerification:
    """The self-check that catches a codec which does not preserve pixels."""

    def test_it_is_on_by_default_and_passes_for_ffv1(self, cover, tmp_path):
        result = video_stego.embed_video(cover, str(tmp_path / "s.mkv"), PAYLOAD, 2, 0)
        assert os.path.isfile(result.output_path)

    def test_it_can_be_turned_off(self, cover, tmp_path):
        result = video_stego.embed_video(
            cover, str(tmp_path / "s.mkv"), PAYLOAD, 2, 0, verify_round_trip=False
        )
        assert video_stego.extract_video(result.output_path, 2, 0) == PAYLOAD

    def test_a_lossy_encoder_would_be_caught_rather_than_trusted(
        self, cover, tmp_path, monkeypatch
    ):
        """Forced by making the writer use a lossy codec.

        Without this check the resulting file would look fine and fail much later, at
        verification, with nothing to point at. The whole value of the check is that
        the failure names its cause, so the message is asserted too.
        """
        original = video_stego.write_frames

        def lossy(frames, path, descriptor, *, overwrite=False, codec=None):
            return original(
                frames, path, descriptor, overwrite=overwrite, codec="MJPG"
            )

        monkeypatch.setattr(video_stego, "write_frames", lossy)

        with pytest.raises(DecodeError) as caught:
            video_stego.embed_video(cover, str(tmp_path / "s.mkv"), PAYLOAD, 1, 0)

        message = str(caught.value)
        assert "did not preserve the pixels" in message
        # And the unusable file was not left behind for someone to send.
        assert not os.path.isfile(str(tmp_path / "s.mkv"))


# --------------------------------------------------------------------------- #
# Through the facade
# --------------------------------------------------------------------------- #


class TestThroughTheFacade:
    def test_video_is_registered(self):
        assert media.supports(constants.MEDIA_VIDEO)

    def test_dispatch_is_by_content(self, cover, tmp_path):
        """The extension says .mkv here, but detection never looks at it."""
        capacity = media.measure(cover, 1)
        assert capacity.media_type == constants.MEDIA_VIDEO

    def test_the_facade_round_trips(self, cover, tmp_path):
        result = media.embed(cover, str(tmp_path / "s.mkv"), PAYLOAD, 2, 100)

        assert result.media_type == constants.MEDIA_VIDEO
        assert result.payload_length == len(PAYLOAD)
        assert media.extract(result.output_path, 2, 100) == PAYLOAD

    def test_the_unified_fields_agree_with_the_layer(self, cover, tmp_path):
        direct = video_stego.embed_video(
            cover, str(tmp_path / "direct.mkv"), PAYLOAD, 2, 0
        )
        through = media.embed(cover, str(tmp_path / "facade.mkv"), PAYLOAD, 2, 0)

        assert through.samples_written == direct.samples_written
        assert through.encoded_length == direct.encoded_length
        assert through.total_samples == direct.capacity.total_embeddable_samples


# --------------------------------------------------------------------------- #
# End to end
# --------------------------------------------------------------------------- #


def protect_clip(cover, tmp_path, keys, *, depth=2, name="stego", **extra):
    private_key, public_key = keys
    public_path = str(tmp_path / "public.pem")
    key_manager.save_public_key(public_key, public_path, overwrite=True)

    result = protect_media(
        cover,
        str(tmp_path / f"{name}.mkv"),
        PAYLOAD,
        private_key,
        media_id="VID-001",
        lsb_depth=depth,
        start_secret=START_SECRET,
        **FAST_SCRYPT,
        **extra,
    )
    return result, public_path


class TestEndToEnd:
    def test_a_protected_clip_verifies(self, big_cover, tmp_path, keys):
        result, public_path = protect_clip(big_cover, tmp_path, keys)

        outcome = verify_media(
            result.stego_path,
            result.manifest_path,
            public_path,
            start_secret=START_SECRET,
        )
        assert outcome.verdict == verdicts.VERDICT_AUTHENTIC
        assert outcome.message == PAYLOAD
        assert outcome.record.media_type == constants.MEDIA_VIDEO

    def test_the_manifest_records_video_media(self, big_cover, tmp_path, keys):
        result, _ = protect_clip(big_cover, tmp_path, keys)
        assert result.manifest.media_type == constants.MEDIA_VIDEO

    def test_the_wrong_secret_does_not_verify(self, big_cover, tmp_path, keys):
        result, public_path = protect_clip(big_cover, tmp_path, keys)

        outcome = verify_media(
            result.stego_path,
            result.manifest_path,
            public_path,
            start_secret="not the secret",
        )
        assert outcome.verdict != verdicts.VERDICT_AUTHENTIC

    def test_a_manual_start_location_verifies(self, big_cover, tmp_path, keys):
        private_key, public_key = keys
        public_path = str(tmp_path / "public.pem")
        key_manager.save_public_key(public_key, public_path, overwrite=True)

        result = protect_media(
            big_cover,
            str(tmp_path / "manual.mkv"),
            PAYLOAD,
            private_key,
            media_id="VID-MANUAL",
            lsb_depth=2,
            start_method=constants.START_METHOD_MANUAL,
            manual_start_location=5_000,
            **FAST_SCRYPT,
        )
        outcome = verify_media(result.stego_path, result.manifest_path, public_path)
        assert outcome.verdict == verdicts.VERDICT_AUTHENTIC

    def test_an_encrypted_message_round_trips(self, big_cover, tmp_path, keys):
        result, public_path = protect_clip(
            big_cover, tmp_path, keys, name="encrypted", passphrase="a passphrase"
        )
        outcome = verify_media(
            result.stego_path,
            result.manifest_path,
            public_path,
            start_secret=START_SECRET,
            passphrase="a passphrase",
        )
        assert outcome.verdict == verdicts.VERDICT_AUTHENTIC
        assert outcome.message == PAYLOAD

    def test_repetition_coding_works_on_video_too(self, big_cover, tmp_path, keys):
        from app.crypto.envelope import ErrorCorrectionParameters

        result, public_path = protect_clip(
            big_cover,
            tmp_path,
            keys,
            depth=3,
            name="coded",
            ecc=ErrorCorrectionParameters(constants.ECC_REPETITION, 3),
        )
        assert result.embedded_length == result.envelope_length * 3

        outcome = verify_media(
            result.stego_path,
            result.manifest_path,
            public_path,
            start_secret=START_SECRET,
        )
        assert outcome.verdict == verdicts.VERDICT_AUTHENTIC


# --------------------------------------------------------------------------- #
# Attacks
# --------------------------------------------------------------------------- #


class TestVideoAttacks:
    def _run(self, result, public_path, tmp_path, key, name, **options):
        context = registry.context_from_manifest(
            result.stego_path,
            result.manifest_path,
            str(tmp_path / f"{name}.mkv"),
            start_secret=START_SECRET,
            **options,
        )
        return registry.run_attack(
            key, context, public_path, start_secret=START_SECRET
        )

    def test_the_catalogue_offers_the_video_attacks(self):
        keys = {a.key for a in registry.available_attacks(constants.MEDIA_VIDEO)}
        assert {"video.inside", "video.outside", "video.drop_frames", "video.lossy"} <= keys

    def test_corruption_inside_the_payload_breaks_verification(
        self, big_cover, tmp_path, keys
    ):
        result, public_path = protect_clip(big_cover, tmp_path, keys)
        run = self._run(result, public_path, tmp_path, "video.inside", "inside")

        assert run.before.verdict == verdicts.VERDICT_AUTHENTIC
        assert run.after.verdict != verdicts.VERDICT_AUTHENTIC
        assert run.matched_expectation

    def test_corruption_outside_the_payload_still_verifies(
        self, big_cover, tmp_path, keys
    ):
        """The honest limitation, demonstrated on the third medium as well."""
        result, public_path = protect_clip(big_cover, tmp_path, keys)
        run = self._run(result, public_path, tmp_path, "video.outside", "outside")

        assert run.after.verdict == verdicts.VERDICT_AUTHENTIC
        assert run.matched_expectation
        assert constants.AUTHENTIC_SCOPE_NOTICE in run.outcome.details.values()

    def test_a_lossy_re_encode_destroys_the_payload(self, big_cover, tmp_path, keys):
        """The single most important video attack: it is what an upload does."""
        result, public_path = protect_clip(big_cover, tmp_path, keys)
        run = self._run(result, public_path, tmp_path, "video.lossy", "lossy")

        assert run.before.verdict == verdicts.VERDICT_AUTHENTIC
        assert run.after.verdict != verdicts.VERDICT_AUTHENTIC
        assert run.matched_expectation
        assert run.outcome.details["codec"] in {
            codec for codec, _ in video_attacks.LOSSY_CODEC_CANDIDATES
        }

    def test_dropping_frames_makes_the_payload_unfindable(
        self, big_cover, tmp_path, keys
    ):
        result, public_path = protect_clip(big_cover, tmp_path, keys)
        run = self._run(
            result, public_path, tmp_path, "video.drop_frames", "dropped", drop_first=2
        )

        assert run.after.verdict != verdicts.VERDICT_AUTHENTIC
        assert run.outcome.details["frames_after"] == (
            run.outcome.details["frames_before"] - 2
        )

    def test_dropping_every_frame_is_refused(self, big_cover, tmp_path, keys):
        from app.attacks.base import AttackError

        result, public_path = protect_clip(big_cover, tmp_path, keys)
        with pytest.raises(AttackError, match="drop fewer"):
            self._run(
                result,
                public_path,
                tmp_path,
                "video.drop_frames",
                "all",
                drop_first=99,
            )

    def test_the_payload_attacks_work_on_video(self, big_cover, tmp_path, keys):
        """They are media-agnostic, and this is where that gets checked for video."""
        result, public_path = protect_clip(big_cover, tmp_path, keys)
        run = self._run(result, public_path, tmp_path, "payload.signature", "forged")

        assert run.after.verdict == verdicts.VERDICT_SIGNATURE_INVALID


# --------------------------------------------------------------------------- #
# Quality and comparison
# --------------------------------------------------------------------------- #


class TestQuality:
    def test_identical_clips_report_no_distortion(self, cover, tmp_path):
        copy = str(tmp_path / "copy.mkv")
        write_video_file(str(tmp_path), make_video_frames(), "copy")

        report = quality_metrics.compare_quality(cover, copy)
        assert report.media_type == constants.MEDIA_VIDEO
        assert report.identical
        assert report.psnr_unbounded

    def test_an_embedding_reports_distortion_within_the_depth_bound(
        self, cover, tmp_path
    ):
        depth = 3
        result = video_stego.embed_video(
            cover, str(tmp_path / "s.mkv"), PAYLOAD, depth, 0
        )

        report = quality_metrics.compare_quality(
            cover, result.output_path, lsb_depth=depth
        )
        assert report.changed_samples > 0
        assert report.within_distortion_bound is True
        assert report.max_absolute_difference <= (1 << depth) - 1

    def test_the_worst_frame_is_reported_separately(self, big_cover, tmp_path):
        """A clip-wide average hides which frames were touched; the worst does not."""
        result = video_stego.embed_video(
            big_cover, str(tmp_path / "s.mkv"), PAYLOAD, 2, 0
        )
        report = quality_metrics.compare_quality(big_cover, result.output_path)

        assert report.extra["frames_changed"] == result.frames_touched
        assert report.extra["worst_frame_index"] == result.first_frame_touched
        assert report.extra["worst_frame_mse"] > report.mse

    def test_clips_of_different_shapes_are_refused(self, cover, video_factory):
        from app.stego.errors import ComparisonError

        other = video_factory(frame_count=8, height=48, width=64, name="other")
        with pytest.raises(ComparisonError, match="cannot be compared"):
            quality_metrics.compare_quality(cover, other)


class TestMediaComparison:
    def test_the_comparison_reports_the_video_properties(self, cover, tmp_path):
        result = video_stego.embed_video(
            cover, str(tmp_path / "s.mkv"), PAYLOAD, 2, 0
        )
        comparison = media_compare.compare(cover, result.output_path, lsb_depth=2)

        labels = {row.label for row in comparison.rows}
        assert {"Resolution", "Frame rate", "Frames", "Duration", "Codec"} <= labels

    def test_the_comparison_includes_the_distortion(self, cover, tmp_path):
        result = video_stego.embed_video(
            cover, str(tmp_path / "s.mkv"), PAYLOAD, 2, 0
        )
        comparison = media_compare.compare(cover, result.output_path, lsb_depth=2)

        assert comparison.quality is not None
        assert comparison.quality.media_type == constants.MEDIA_VIDEO

    def test_the_notes_warn_that_the_average_understates_the_touched_frames(
        self, cover, tmp_path
    ):
        result = video_stego.embed_video(
            cover, str(tmp_path / "s.mkv"), PAYLOAD, 2, 0
        )
        comparison = media_compare.compare(cover, result.output_path)

        assert any("worst-frame" in note for note in comparison.notes)


# --------------------------------------------------------------------------- #
# The Video tab
# --------------------------------------------------------------------------- #


class TestFrameSpan:
    """The arithmetic the tab shows, tested without a window."""

    def test_a_payload_inside_one_frame_reports_one_frame(self, cover):
        from app.gui.video_tab import frame_span_for

        descriptor = video_stego.describe_only(cover)
        span = frame_span_for(descriptor, 0, 100, 8)

        assert span.first_frame == 0
        assert span.last_frame == 0
        assert span.frames_touched == 1
        assert span.covers(0)
        assert not span.covers(1)

    def test_a_payload_crossing_a_boundary_reports_both_frames(self, cover):
        from app.gui.video_tab import frame_span_for

        descriptor = video_stego.describe_only(cover)
        start = descriptor.samples_per_frame - 40
        span = frame_span_for(descriptor, start, 64, 1)

        assert span.first_frame == 0
        assert span.last_frame == 1
        assert span.frames_touched == 2

    def test_the_offset_within_the_first_frame_is_reported(self, cover):
        from app.gui.video_tab import frame_span_for

        descriptor = video_stego.describe_only(cover)
        per_frame = descriptor.samples_per_frame
        span = frame_span_for(descriptor, per_frame + 17, 32, 1)

        assert span.first_frame == 1
        assert span.offset_within_first_frame() == 17

    def test_it_agrees_with_what_the_embedding_actually_touched(self, cover, tmp_path):
        """The figure the tab shows has to be the figure the layer produced."""
        from app.gui.video_tab import frame_span_for

        descriptor = video_stego.describe_only(cover)
        start = descriptor.samples_per_frame - 40
        payload = bytes(range(80))

        result = video_stego.embed_video(
            cover, str(tmp_path / "s.mkv"), payload, 1, start
        )
        span = frame_span_for(descriptor, start, len(payload), 1)

        assert span.samples_written == result.samples_written
        assert span.first_frame == result.first_frame_touched
        assert span.last_frame == result.last_frame_touched


class TestVideoTab:
    @pytest.fixture()
    def tab(self, qtbot):
        from app.gui.video_tab import VideoTab

        widget = VideoTab()
        qtbot.addWidget(widget)
        return widget

    def test_it_only_accepts_video(self, tab, cover, tmp_path):
        assert tab.drop_zone.accept_path(cover) is True

        image = tmp_path / "not-video.png"
        from app.stego import image_io

        from conftest import make_cover

        image.write_bytes(image_io.encode_image(make_cover(8, 8, 3), image_io.PNG))
        assert tab.drop_zone.accept_path(str(image)) is False

    def test_locating_needs_a_clip_first(self, tab):
        assert "Select a clip" in tab.locate_validation_error()

    def test_it_reports_the_payload_frames_from_the_manifest(
        self, tab, big_cover, tmp_path, keys, qtbot
    ):
        result, _ = protect_clip(big_cover, tmp_path, keys)

        # Describe synchronously rather than through the worker, so the test does
        # not depend on thread timing.
        tab._path = result.stego_path
        tab._on_described(video_stego.describe_only(result.stego_path))
        tab.manifest_edit.setText(result.manifest_path)
        tab.secret_edit.setText(START_SECRET)

        tab.locate_payload()

        assert tab.span is not None
        assert tab.span.start_location == result.start_location
        assert tab.span.frames_touched >= 1

    def test_a_missing_secret_is_reported_rather_than_guessed(
        self, tab, big_cover, tmp_path, keys
    ):
        result, _ = protect_clip(big_cover, tmp_path, keys)

        tab._path = result.stego_path
        tab._on_described(video_stego.describe_only(result.stego_path))
        tab.manifest_edit.setText(result.manifest_path)

        tab.locate_payload()
        assert tab.span is None

    def test_the_capacity_table_covers_every_depth(self, tab, cover):
        tab._path = cover
        tab._on_described(video_stego.describe_only(cover))

        assert tab.capacity_table.rowCount() == len(constants.LSB_DEPTHS)

    def test_a_frame_that_carries_no_payload_says_so(
        self, tab, big_cover, tmp_path, keys
    ):
        result, _ = protect_clip(big_cover, tmp_path, keys)

        tab._path = result.stego_path
        tab._on_described(video_stego.describe_only(result.stego_path))
        tab.manifest_edit.setText(result.manifest_path)
        tab.secret_edit.setText(START_SECRET)
        tab.locate_payload()

        # Pick a frame the payload does not reach.
        outside = (tab.span.last_frame + 1) % tab.span.frame_count
        if outside == tab.span.first_frame:  # pragma: no cover - tiny clip guard
            pytest.skip("the payload covers the whole clip")
        tab.frame_slider.setValue(outside)

        assert "carries no payload" in tab.carrier_label.text()
