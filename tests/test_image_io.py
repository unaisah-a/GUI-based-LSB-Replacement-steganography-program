"""Tests for lossless loading, format detection and atomic saving (Requirement 1, 6.5-6.8).

Requirement 15.9 asks for a small number of representative example tests for file
format handling rather than property tests, because the interesting cases are
specific container variants rather than a broad input space.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path

import numpy as np
import pytest
from PIL import Image

from app.stego import image_io
from app.stego.errors import DecodeError, FileError, ValidationError

from conftest import make_cover, write_cover


class TestLosslessRoundTrip:
    """Requirement 1.4: samples survive a save-and-reload cycle exactly."""

    @pytest.mark.parametrize(
        ("channels", "container"),
        [
            (1, image_io.PNG),
            (3, image_io.PNG),
            (4, image_io.PNG),
            (3, image_io.BMP),
            (4, image_io.BMP),
        ],
    )
    def test_round_trip(self, workspace, channels, container):
        array = make_cover(9, 13, channels, "noise", 4)
        path = write_cover(workspace, array, container, "cover")
        reloaded, descriptor = image_io.load_image(path)
        assert np.array_equal(array, reloaded)
        assert descriptor.container_format == container
        assert descriptor.shape == (9, 13, channels)
        assert descriptor.sample_width_bits == 8

    @pytest.mark.parametrize("width", [1, 2, 3, 4, 5, 7, 8, 13])
    def test_bmp_row_padding_widths(self, workspace, width):
        """BMP rows are padded to 4 bytes, so odd widths are the risky ones."""
        array = make_cover(3, width, 3, "noise", width)
        path = write_cover(workspace, array, image_io.BMP, "cover")
        reloaded, _ = image_io.load_image(path)
        assert np.array_equal(array, reloaded)

    def test_alpha_survives_a_bmp_round_trip(self, workspace):
        """Pillow's own BMP writer drops alpha; this layer must not.

        This is why the module encodes BMP itself, writing a BITMAPV4HEADER with
        an explicit alpha mask rather than a 32-bit BI_RGB bitmap.
        """
        array = make_cover(6, 6, 4, "noise", 2)
        array[:, :, 3] = np.arange(36, dtype=np.uint8).reshape(6, 6)
        path = write_cover(workspace, array, image_io.BMP, "cover")
        reloaded, descriptor = image_io.load_image(path)
        assert descriptor.channel_count == 4
        assert np.array_equal(array[:, :, 3], reloaded[:, :, 3])

    def test_single_pixel_image(self, workspace):
        array = make_cover(1, 1, 3, "flat", 1)
        path = write_cover(workspace, array, image_io.PNG, "cover")
        reloaded, descriptor = image_io.load_image(path)
        assert np.array_equal(array, reloaded)
        assert descriptor.shape == (1, 1, 3)

    def test_grayscale_returns_a_three_dimensional_array(self, workspace):
        path = write_cover(
            workspace, make_cover(4, 4, 1, "noise", 1), image_io.PNG, "cover"
        )
        array, _ = image_io.load_image(path)
        assert array.ndim == 3
        assert array.shape[2] == 1


class TestFormatDetection:
    """Requirement 1.1 and 1.2: content decides, not the extension."""

    def test_content_wins_over_extension(self, workspace):
        array = make_cover(5, 5, 3, "noise", 1)
        path = os.path.join(workspace, "actually_a_png.bmp")
        with open(path, "wb") as handle:
            handle.write(image_io.encode_image(array, image_io.PNG))

        reloaded, descriptor = image_io.load_image(path)
        assert descriptor.container_format == image_io.PNG
        assert descriptor.extension_format == image_io.BMP
        assert np.array_equal(array, reloaded)

    def test_matching_extension_is_reported(self, workspace):
        path = write_cover(
            workspace, make_cover(5, 5, 3, "noise", 1), image_io.PNG, "cover"
        )
        descriptor = image_io.describe_only(path)
        assert descriptor.extension_format == descriptor.container_format

    def test_unknown_extension_is_not_fatal(self, workspace):
        array = make_cover(5, 5, 3, "noise", 1)
        path = os.path.join(workspace, "cover.dat")
        with open(path, "wb") as handle:
            handle.write(image_io.encode_image(array, image_io.PNG))
        descriptor = image_io.describe_only(path)
        assert descriptor.container_format == image_io.PNG
        assert descriptor.extension_format is None


class TestBmpVariants:
    """Requirement 1.12."""

    def test_bottom_up_and_top_down_decode_identically(self, workspace):
        array = make_cover(5, 7, 3, "gradient", 1)
        encoded = bytearray(image_io.encode_image(array, image_io.BMP))

        height = struct.unpack("<i", encoded[22:26])[0]
        assert height > 0, "this module writes bottom-up BMP by default"

        stride = ((24 * 7 + 31) // 32) * 4
        offset = 14 + 40
        rows = [
            bytes(encoded[offset + index * stride : offset + (index + 1) * stride])
            for index in range(5)
        ]
        # Flip the declared order and physically reverse the stored rows, which
        # should describe the very same image.
        encoded[22:26] = struct.pack("<i", -height)
        encoded[offset : offset + stride * 5] = b"".join(reversed(rows))

        path = os.path.join(workspace, "topdown.bmp")
        with open(path, "wb") as handle:
            handle.write(bytes(encoded))

        reloaded, descriptor = image_io.load_image(path)
        assert descriptor.bmp_bottom_up is False
        assert np.array_equal(array, reloaded)

    def test_thirty_two_bit_bmp_decodes_as_four_channels(self, workspace):
        path = write_cover(
            workspace, make_cover(4, 4, 4, "noise", 1), image_io.BMP, "cover"
        )
        _, descriptor = image_io.load_image(path)
        assert descriptor.channel_count == 4
        assert descriptor.bmp_header_size == 108  # BITMAPV4HEADER

    def test_bitmapcoreheader_is_rejected(self, workspace):
        encoded = bytearray(
            image_io.encode_image(make_cover(4, 4, 3, "noise", 1), image_io.BMP)
        )
        encoded[14:18] = struct.pack("<I", 12)
        path = os.path.join(workspace, "core.bmp")
        with open(path, "wb") as handle:
            handle.write(bytes(encoded))
        with pytest.raises(DecodeError, match="BITMAPCOREHEADER"):
            image_io.load_image(path)

    def test_rle_compressed_bmp_is_rejected(self, workspace):
        encoded = bytearray(
            image_io.encode_image(make_cover(4, 4, 3, "noise", 1), image_io.BMP)
        )
        encoded[30:34] = struct.pack("<I", 1)  # BI_RLE8
        path = os.path.join(workspace, "rle.bmp")
        with open(path, "wb") as handle:
            handle.write(bytes(encoded))
        with pytest.raises(DecodeError, match="RLE8"):
            image_io.load_image(path)

    def test_sixteen_bit_bmp_is_rejected(self, workspace):
        encoded = bytearray(
            image_io.encode_image(make_cover(4, 4, 3, "noise", 1), image_io.BMP)
        )
        encoded[28:30] = struct.pack("<H", 16)
        path = os.path.join(workspace, "packed.bmp")
        with open(path, "wb") as handle:
            handle.write(bytes(encoded))
        with pytest.raises(DecodeError, match="16-bit"):
            image_io.load_image(path)

    def test_oversized_dimensions_are_rejected_before_reading_pixels(self, workspace):
        encoded = bytearray(
            image_io.encode_image(make_cover(4, 4, 3, "noise", 1), image_io.BMP)
        )
        encoded[18:22] = struct.pack("<i", 40_000)
        path = os.path.join(workspace, "huge.bmp")
        with open(path, "wb") as handle:
            handle.write(bytes(encoded))
        with pytest.raises(DecodeError, match="outside the supported range"):
            image_io.load_image(path)

    def test_truncated_bmp_is_rejected(self, workspace):
        encoded = image_io.encode_image(make_cover(8, 8, 3, "noise", 1), image_io.BMP)
        path = os.path.join(workspace, "short.bmp")
        with open(path, "wb") as handle:
            handle.write(encoded[: len(encoded) // 2])
        with pytest.raises(DecodeError, match="truncated"):
            image_io.load_image(path)


class TestPngVariants:
    """Requirement 1.6, 1.7, 1.10 and 1.11."""

    def test_no_ancillary_chunks_are_written(self, workspace):
        """Requirement 1.11: only the records needed to represent the image."""
        path = write_cover(
            workspace, make_cover(5, 5, 3, "noise", 1), image_io.PNG, "cover"
        )
        raw = Path(path).read_bytes()
        offset = 8
        chunks = []
        while offset < len(raw):
            length = struct.unpack(">I", raw[offset : offset + 4])[0]
            chunks.append(raw[offset + 4 : offset + 8].decode("ascii"))
            offset += 12 + length
        assert chunks == ["IHDR", "IDAT", "IEND"]

    def test_source_metadata_is_not_carried_over(self, workspace):
        """A cover carrying a text chunk must not leak it into the stego object."""
        from PIL import PngImagePlugin

        source = os.path.join(workspace, "with_metadata.png")
        info = PngImagePlugin.PngInfo()
        info.add_text("Comment", "sensitive provenance note")
        Image.fromarray(make_cover(5, 5, 3, "noise", 1), "RGB").save(
            source, pnginfo=info
        )
        assert b"sensitive provenance note" in Path(source).read_bytes()

        array, descriptor = image_io.load_image(source)
        output = os.path.join(workspace, "clean.png")
        image_io.save_image(array, output, descriptor.container_format)
        assert b"sensitive provenance note" not in Path(output).read_bytes()

    def test_written_png_is_not_interlaced(self, workspace):
        """Requirement 1.10 output side.

        The input side of Requirement 1.10 is not covered by a test: Pillow
        ignores its ``interlace`` save argument, so no genuine Adam7 PNG can be
        produced here to decode. The interlace flag is read from IHDR byte 28 and
        reported, and Pillow decodes Adam7 transparently, but that path is
        untested rather than verified.
        """
        path = write_cover(
            workspace, make_cover(5, 5, 3, "noise", 1), image_io.PNG, "cover"
        )
        assert image_io.describe_only(path).interlaced is False

    def test_one_bit_png_is_rejected(self, workspace):
        path = os.path.join(workspace, "bilevel.png")
        Image.fromarray(
            make_cover(8, 8, 1, "stripes", 1)[:, :, 0] > 0
        ).save(path)
        with pytest.raises(DecodeError, match="sample width"):
            image_io.load_image(path)

    def test_palette_png_is_rejected(self, workspace):
        path = os.path.join(workspace, "palette.png")
        Image.fromarray(make_cover(8, 8, 3, "noise", 1), "RGB").convert("P").save(path)
        with pytest.raises(DecodeError, match="palette"):
            image_io.load_image(path)

    def test_missing_ihdr_is_rejected(self, workspace):
        path = os.path.join(workspace, "broken.png")
        with open(path, "wb") as handle:
            handle.write(b"\x89PNG\r\n\x1a\n" + b"\x00" * 40)
        with pytest.raises(DecodeError, match="IHDR"):
            image_io.load_image(path)


class TestLossyRejection:
    """Requirement 1.5."""

    @pytest.mark.parametrize(
        ("fmt", "pattern"), [("JPEG", "JPEG"), ("GIF", "GIF"), ("TIFF", "TIFF")]
    )
    def test_lossy_and_unsupported_containers(self, workspace, fmt, pattern):
        path = os.path.join(workspace, f"image.{fmt.lower()}")
        Image.fromarray(make_cover(16, 16, 3, "noise", 1), "RGB").save(path, format=fmt)
        with pytest.raises(DecodeError, match=pattern):
            image_io.load_image(path)

    def test_error_names_the_supported_formats(self, workspace):
        path = os.path.join(workspace, "image.jpg")
        Image.fromarray(make_cover(16, 16, 3, "noise", 1), "RGB").save(
            path, format="JPEG"
        )
        with pytest.raises(DecodeError) as info:
            image_io.load_image(path)
        assert "PNG" in str(info.value) and "BMP" in str(info.value)


class TestFileErrors:
    """Requirement 14.1, 14.5 and 14.8."""

    def test_missing_file(self, workspace):
        with pytest.raises(FileError, match="not found"):
            image_io.load_image(os.path.join(workspace, "absent.png"))

    def test_directory_as_input(self, workspace):
        with pytest.raises(FileError, match="directory"):
            image_io.load_image(workspace)

    def test_missing_output_directory(self, workspace):
        array = make_cover(4, 4, 3, "noise", 1)
        with pytest.raises(FileError, match="output directory"):
            image_io.save_image(
                array, os.path.join(workspace, "absent", "o.png"), image_io.PNG
            )

    def test_message_excludes_the_directory(self, workspace):
        missing = os.path.join(workspace, "absent.png")
        with pytest.raises(FileError) as info:
            image_io.load_image(missing)
        assert "absent.png" in str(info.value)
        assert workspace not in str(info.value)


class TestEncodeValidation:
    def test_grayscale_bmp_output_is_refused(self):
        """BMP stores 8-bit grayscale as a palette image, which this layer rejects.

        Refusing to write it is better than writing a file the loader would then
        reject as unsupported.
        """
        with pytest.raises(ValidationError, match="grayscale output"):
            image_io.encode_image(make_cover(4, 4, 1, "noise", 1), image_io.BMP)

    def test_unknown_container(self):
        with pytest.raises(ValidationError, match="container_format"):
            image_io.encode_image(make_cover(4, 4, 3, "noise", 1), "TIFF")

    def test_wrong_dtype(self):
        with pytest.raises(ValidationError, match="uint8"):
            image_io.encode_image(
                np.zeros((4, 4, 3), dtype=np.uint16), image_io.PNG
            )

    def test_wrong_channel_count(self):
        with pytest.raises(ValidationError, match="channels"):
            image_io.encode_image(np.zeros((4, 4, 2), dtype=np.uint8), image_io.PNG)


class TestAtomicSave:
    """Requirement 6.5 to 6.8."""

    def test_overwrite_flag_is_required(self, workspace):
        array = make_cover(4, 4, 3, "noise", 1)
        path = os.path.join(workspace, "out.png")
        image_io.save_image(array, path, image_io.PNG)
        with pytest.raises(FileError, match="already occupied"):
            image_io.save_image(array, path, image_io.PNG)
        image_io.save_image(array, path, image_io.PNG, overwrite=True)

    def test_replace_is_retried_then_succeeds(self, workspace, monkeypatch):
        """Requirement 6.8: Windows fails the replace while a reader holds the file."""
        array = make_cover(4, 4, 3, "noise", 1)
        path = os.path.join(workspace, "out.png")
        real_replace = os.replace
        attempts = {"count": 0}

        def flaky_replace(source, destination):
            attempts["count"] += 1
            if attempts["count"] < 3:
                raise PermissionError("destination is held open by another process")
            return real_replace(source, destination)

        monkeypatch.setattr(os, "replace", flaky_replace)
        image_io.save_image(
            array, path, image_io.PNG, replace_delay_seconds=0.0
        )
        assert attempts["count"] == 3
        assert os.path.isfile(path)
        assert [n for n in os.listdir(workspace) if n.startswith(".partial-")] == []

    def test_replace_gives_up_after_the_attempt_limit(self, workspace, monkeypatch):
        array = make_cover(4, 4, 3, "noise", 1)
        path = os.path.join(workspace, "out.png")

        def always_fails(source, destination):
            raise PermissionError("held open")

        monkeypatch.setattr(os, "replace", always_fails)
        with pytest.raises(FileError, match="could not be replaced"):
            image_io.save_image(array, path, image_io.PNG, replace_delay_seconds=0.0)
        # Requirement 6.7: the temporary file is cleaned up on the failure path.
        assert [n for n in os.listdir(workspace) if n.startswith(".partial-")] == []
        assert not os.path.exists(path)

    def test_no_temporary_file_survives_an_encode_failure(self, workspace):
        with pytest.raises(ValidationError):
            image_io.save_image(
                make_cover(4, 4, 1, "noise", 1),
                os.path.join(workspace, "out.bmp"),
                image_io.BMP,
            )
        assert [n for n in os.listdir(workspace) if n.startswith(".partial-")] == []
