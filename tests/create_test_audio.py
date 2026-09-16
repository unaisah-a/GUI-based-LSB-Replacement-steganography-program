import numpy as np
import soundfile as sf

sample_rate = 44100
duration = 10

t = np.linspace(
    0,
    duration,
    sample_rate * duration,
    endpoint=False
)

# Simple test tone.
audio = 0.3 * np.sin(2 * np.pi * 440 * t)

audio = audio.astype(np.float32)

sf.write(
    "samples/audio/original/original.wav",
    audio,
    sample_rate,
    subtype="PCM_16"
)

print("Test audio created.")