"""Preview and playback for the three media types.

The plan requires cover and stego objects to be displayed or played before and after
encoding, so this widget has to handle a still image, an audio track and a video
clip behind one interface. It switches between a pixmap view and a media player
depending on what it is given.

Degrading rather than failing
-----------------------------
QtMultimedia depends on platform codecs that are not always present — notably on a
headless machine, and on some Windows installations without the media feature pack.
Rather than let a missing backend crash the window, the player is created lazily and
a failure is caught: the widget then shows a message saying playback is unavailable
and everything else in the tab keeps working. That matters because the image path,
which is the bulk of the demonstration, does not need QtMultimedia at all.

The status is exposed as :attr:`MediaPreview.playback_available` so a caller can say
so in the interface instead of leaving a dead button. A missing backend does not
raise: Qt creates the player anyway and reports it through ``isAvailable()``, so that
is checked explicitly.

Finding the FFmpeg backend on Windows
-------------------------------------
Qt 6.8 plays media through an FFmpeg plugin whose FFmpeg DLLs sit in the PySide6
package directory. Some Windows interpreters, notably the Microsoft Store build of
Python, do not search that directory, so the plugin fails to load and Qt reports no
backend at all. :func:`_allow_bundled_ffmpeg` adds the directory to the DLL search
path before the first player is created.
"""

from __future__ import annotations

import os
import sys

from PySide6.QtCore import Qt, QUrl, Signal
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QSlider,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from app.utils import constants, file_utils
from app.utils.logging_utils import get_logger

__all__ = ["MediaPreview"]

_log = get_logger(__name__)

_ffmpeg_directory_added = False
_ffmpeg_directory_handle = None


def _allow_bundled_ffmpeg() -> None:
    """Let Qt's FFmpeg media plugin find the FFmpeg DLLs shipped with PySide6.

    A no-op except on Windows, and done at most once.
    """
    global _ffmpeg_directory_added, _ffmpeg_directory_handle
    if _ffmpeg_directory_added or sys.platform != "win32":
        return
    import PySide6

    try:
        _ffmpeg_directory_handle = os.add_dll_directory(
            os.path.dirname(os.path.abspath(PySide6.__file__))
        )
    except OSError as exc:  # pragma: no cover - an unusual installation
        _log.warning("could not add the PySide6 DLL directory: %s", exc)
    _ffmpeg_directory_added = True


class MediaPreview(QWidget):
    """Shows an image, or plays audio or video."""

    #: Emitted when the widget could not present the supplied file.
    previewFailed = Signal(str)

    def __init__(self, parent: QWidget | None = None, *, title: str = "") -> None:
        super().__init__(parent)
        self.setObjectName("mediaPreview")

        self._path: str | None = None
        self._player = None
        self._audio_output = None
        self._video_widget = None
        self._playback_available: bool | None = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        if title:
            heading = QLabel(title, self)
            heading.setObjectName("mediaPreviewTitle")
            outer.addWidget(heading)

        self._stack = QStackedWidget(self)
        self._stack.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        outer.addWidget(self._stack, 1)

        # Page 0: a message, used when empty or when something is unavailable.
        self._message_label = QLabel("Nothing to preview.", self)
        self._message_label.setObjectName("mediaPreviewMessage")
        self._message_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._message_label.setWordWrap(True)
        self._message_label.setTextFormat(Qt.TextFormat.PlainText)
        self._stack.addWidget(self._message_label)

        # Page 1: a still image.
        self._image_label = QLabel(self)
        self._image_label.setObjectName("mediaPreviewImage")
        self._image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._image_label.setMinimumSize(160, 120)
        self._stack.addWidget(self._image_label)

        # Page 2 is added lazily, only if a media player can be created.
        self._player_page: QWidget | None = None

        self._controls = QWidget(self)
        controls_layout = QHBoxLayout(self._controls)
        controls_layout.setContentsMargins(0, 0, 0, 0)

        self._play_button = QPushButton("Play", self._controls)
        self._play_button.clicked.connect(self.toggle_playback)
        controls_layout.addWidget(self._play_button)

        self._stop_button = QPushButton("Stop", self._controls)
        self._stop_button.clicked.connect(self.stop)
        controls_layout.addWidget(self._stop_button)

        self._position_slider = QSlider(Qt.Orientation.Horizontal, self._controls)
        self._position_slider.setRange(0, 0)
        self._position_slider.sliderMoved.connect(self._seek)
        controls_layout.addWidget(self._position_slider, 1)

        self._time_label = QLabel("0:00", self._controls)
        controls_layout.addWidget(self._time_label)

        self._controls.setVisible(False)
        outer.addWidget(self._controls)

        self._caption = QLabel("", self)
        self._caption.setObjectName("mediaPreviewCaption")
        self._caption.setWordWrap(True)
        self._caption.setTextFormat(Qt.TextFormat.PlainText)
        outer.addWidget(self._caption)

    # -- state ------------------------------------------------------------- #

    @property
    def path(self) -> str | None:
        return self._path

    @property
    def playback_available(self) -> bool:
        """Whether a media player could be created on this machine."""
        if self._playback_available is None:
            self._playback_available = self._ensure_player()
        return self._playback_available

    def clear(self) -> None:
        self.stop()
        if self._player is not None:
            from shiboken6 import delete

            # Destroy the decoder while its video surface is still alive.
            # setSource(empty) alone leaves asynchronous backend work pending.
            self._player.setSource(QUrl())
            self._player.setVideoOutput(None)
            self._player.setAudioOutput(None)
            delete(self._player)
            self._player = None
            self._audio_output = None
            self._playback_available = None
        self._pixmap = None
        self._path = None
        self._image_label.clear()
        self._caption.setText("")
        self._controls.setVisible(False)
        self._show_message("Nothing to preview.")

    def closeEvent(self, event) -> None:
        # Stop asynchronous decoding before QWidget destroys the video surface.
        # Standalone previews do not have a parent tab's shutdown hook.
        self.clear()
        super().closeEvent(event)

    def _show_message(self, text: str) -> None:
        self._message_label.setText(text)
        self._stack.setCurrentIndex(0)

    # -- loading ----------------------------------------------------------- #

    def show_file(
        self,
        path: str | os.PathLike[str],
        *,
        media_type: str | None = None,
        caption: str | None = None,
    ) -> bool:
        """Present the file at *path*. Returns whether it could be presented.

        By default the type is detected with the cover-object rules, which refuse
        lossy formats. A recovered payload may legitimately be a JPEG or an MP3, so
        a caller that has already identified the content passes *media_type*
        (``"image"`` or ``"audio"``) and a *caption* instead.
        """
        target = os.fspath(path)
        self.stop()
        self._path = target

        if not os.path.isfile(target):
            return self._fail(f"{file_utils.display_name(target)} is not a file")

        if media_type is None:
            try:
                description = file_utils.describe_file(target)
            except file_utils.UnsupportedMediaError as exc:
                return self._fail(str(exc))
            media_type = description.media_type
            caption = (
                f"{description.name} - {description.container_format}, "
                f"{description.size_human}"
            )

        self._caption.setText(caption or file_utils.display_name(target))

        if media_type == constants.MEDIA_IMAGE:
            return self._show_image(target)
        return self._show_playable(target, media_type)

    def _fail(self, reason: str) -> bool:
        self._controls.setVisible(False)
        self._show_message(reason)
        self.previewFailed.emit(reason)
        return False

    def _show_image(self, path: str) -> bool:
        pixmap = QPixmap(path)
        if pixmap.isNull():
            return self._fail(
                f"{file_utils.display_name(path)} could not be shown as an image"
            )

        self._pixmap = pixmap
        self._controls.setVisible(False)
        self._stack.setCurrentIndex(1)
        self._rescale()
        return True

    def _rescale(self) -> None:
        pixmap = getattr(self, "_pixmap", None)
        if pixmap is None or pixmap.isNull():
            return
        # Smooth transformation, but never scaled *up*: enlarging a small cover would
        # blur away exactly the low-order detail a viewer is trying to inspect.
        target = self._image_label.size()
        if pixmap.width() <= target.width() and pixmap.height() <= target.height():
            self._image_label.setPixmap(pixmap)
            return
        self._image_label.setPixmap(
            pixmap.scaled(
                target,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
        )

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        if self._stack.currentIndex() == 1:
            self._rescale()

    def _show_playable(self, path: str, media_type: str) -> bool:
        if not self._ensure_player():
            return self._fail(
                f"Playback is not available on this machine, so this {media_type} "
                f"file cannot be played. Its properties and quality metrics are "
                f"still shown."
            )

        self._player.setSource(QUrl.fromLocalFile(os.path.abspath(path)))
        self._controls.setVisible(True)
        self._play_button.setText("Play")

        if media_type == constants.MEDIA_VIDEO and self._player_page is not None:
            self._stack.setCurrentWidget(self._player_page)
        else:
            self._show_message(f"Ready to play {file_utils.display_name(path)}.")
        return True

    def _ensure_player(self) -> bool:
        """Create the media player once, reporting whether it worked."""
        if self._player is not None:
            return True
        if self._playback_available is False:
            return False

        try:
            _allow_bundled_ffmpeg()
            from PySide6.QtMultimedia import QAudioOutput, QMediaPlayer
            from PySide6.QtMultimediaWidgets import QVideoWidget

            self._player = QMediaPlayer(self)
            if not self._player.isAvailable():
                # No backend could be loaded. Qt does not raise for this; the
                # player exists but can never play anything.
                raise RuntimeError("no QtMultimedia backend is available")
            self._audio_output = QAudioOutput(self._player)
            self._player.setAudioOutput(self._audio_output)

            if self._video_widget is None:
                self._video_widget = QVideoWidget(self)
                self._player_page = self._video_widget
                self._stack.addWidget(self._player_page)
            self._player.setVideoOutput(self._video_widget)

            self._player.positionChanged.connect(self._on_position_changed)
            self._player.durationChanged.connect(self._on_duration_changed)
            self._player.playbackStateChanged.connect(self._on_state_changed)
        except Exception as exc:
            _log.warning("media playback unavailable: %s", exc)
            if self._player is not None:
                from shiboken6 import delete

                delete(self._player)
            self._player = None
            self._audio_output = None
            self._video_widget = None
            self._player_page = None
            self._playback_available = False
            return False

        self._playback_available = True
        return True

    # -- transport --------------------------------------------------------- #

    def toggle_playback(self) -> None:
        if self._player is None:
            return
        from PySide6.QtMultimedia import QMediaPlayer

        if self._player.playbackState() == QMediaPlayer.PlaybackState.PlayingState:
            self._player.pause()
        else:
            self._player.play()

    def stop(self) -> None:
        if self._player is not None:
            self._player.stop()
            self._play_button.setText("Play")

    def _seek(self, position: int) -> None:
        if self._player is not None:
            self._player.setPosition(position)

    def _on_position_changed(self, position: int) -> None:
        self._position_slider.setValue(position)
        self._time_label.setText(self._format_time(position))

    def _on_duration_changed(self, duration: int) -> None:
        self._position_slider.setRange(0, duration)

    def _on_state_changed(self, state) -> None:
        from PySide6.QtMultimedia import QMediaPlayer

        playing = state == QMediaPlayer.PlaybackState.PlayingState
        self._play_button.setText("Pause" if playing else "Play")

    @staticmethod
    def _format_time(milliseconds: int) -> str:
        seconds = max(0, milliseconds // 1000)
        return f"{seconds // 60}:{seconds % 60:02d}"
