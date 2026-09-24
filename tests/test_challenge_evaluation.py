"""Exercise saved-file demonstrations and labelled evaluation end to end."""
from scripts.evaluate_challenges import evaluate


def test_challenge_evaluation(tmp_path):
    result = evaluate(tmp_path / "evaluation")
    assert len(result["workflows"]) == 3
    assert len(result["robustness"]) == 6
    analysis = result["steganalysis"]
    assert len(analysis["cases"]) == 18
    assert analysis["false_positives"] > 0
    assert analysis["misses"] > 0
    assert (tmp_path / "evaluation" / "results.json").is_file()
