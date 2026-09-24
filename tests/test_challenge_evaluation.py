"""Exercise saved-file demonstrations and labelled evaluation end to end."""
from scripts.evaluate_challenges import evaluate


def test_challenge_evaluation(tmp_path):
    result = evaluate(tmp_path / "evaluation")
    assert len(result["workflows"]) == 3
    assert len(result["robustness"]) == 6
    assert "steganalysis" not in result
    assert (tmp_path / "evaluation" / "results.json").is_file()
