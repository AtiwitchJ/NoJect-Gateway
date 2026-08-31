import pytest
from model_evaluator import run_model_benchmark, MODELS

def test_model_evaluator_execution():
    results = run_model_benchmark()
    assert len(results) == len(MODELS)

    for r in results:
        assert r["shielded_defense"] == 100.0, f"Expected 100% defense for {r['model']}"
        assert r["fp_rate"] == 0.0, f"Expected 0% false positive for {r['model']}"
        assert r["f1_score"] == 100.0, f"Expected 100% F1 for {r['model']}"
