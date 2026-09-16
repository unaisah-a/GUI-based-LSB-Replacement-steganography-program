from pathlib import Path

from app.stego.audio_stego import (
    embed_audio_lsb,
    extract_audio_lsb,
)

from app.analysis.audio_analysis import (
    calculate_quality_report,
)


# ============================================================
# SETTINGS
# ============================================================

lsb_count = 4

payload = b"INF2005 Audio Steganography Test"

start_location = 100


# ============================================================
# FILE PATHS
# ============================================================

input_path = Path(
    "samples/audio/original/original.wav"
)

output_path = Path(
    f"samples/audio/stego/stego_lsb{lsb_count}.wav"
)

# Make sure the folder exists.
output_path.parent.mkdir(
    parents=True,
    exist_ok=True
)


# ============================================================
# EMBED PAYLOAD
# ============================================================

embed_result = embed_audio_lsb(
    input_path=input_path,
    output_path=output_path,
    payload=payload,
    lsb_count=lsb_count,
    start_location=start_location
)

print("\nStego audio created:")
print(output_path)


# ============================================================
# EXTRACT PAYLOAD
# ============================================================

extracted_payload = extract_audio_lsb(
    input_path=output_path,
    lsb_count=lsb_count,
    start_location=start_location
)

print("\nExtracted payload:")
print(extracted_payload.decode("utf-8"))


# ============================================================
# QUALITY ANALYSIS
# ============================================================

report = calculate_quality_report(
    input_path,
    output_path,
    lsb_count=lsb_count
)

print("\nAudio Quality Report:")

for key, value in report.items():
    print(f"{key}: {value}")