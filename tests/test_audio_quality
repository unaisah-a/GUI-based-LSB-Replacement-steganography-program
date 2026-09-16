from app.analysis.audio_analysis import calculate_quality_report


report = calculate_quality_report(
    "samples/audio/original/original.wav",
    "samples/audio/stego/stego.wav",
    lsb_count=4
)

for key, value in report.items():
    print(f"{key}: {value}")