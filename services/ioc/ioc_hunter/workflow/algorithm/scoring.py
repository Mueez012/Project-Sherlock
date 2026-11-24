"""Pure paper scoring; cold start and equal-score ordering are explicit."""
import math


def rank_methods(methods, history, input_type, alpha):
    compatible = [method for method in methods if method["input_type"] == input_type]
    total = sum(history[m["id"]]["tried"] for m in compatible)
    rows = []
    for method in compatible:
        counters = history[method["id"]]
        tried, coverage = counters["tried"], counters["coverage"]
        if type(tried) is not int or type(coverage) is not int or not 0 <= coverage <= tried:
            raise ValueError("Invalid saved method history")
        score = (coverage / (tried + 1e-6) + alpha * math.sqrt(math.log(total) / (tried + 1e-6))) if total else 0.0
        if not math.isfinite(score):
            raise ValueError("Nonfinite method score; check alpha and history")
        rows.append({**method, **counters, "score": score, "cold_start": total == 0})
    return sorted(rows, key=lambda row: (-row["score"], row["id"]))[:50]
