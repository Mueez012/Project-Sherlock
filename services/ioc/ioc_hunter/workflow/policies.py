"""Graph admission only. Automatic ranking and Algorithm 1 counters come later."""


class PaperAdmissionPolicy:
    name = "manual-selection/paper-admission-v1"

    def evaluate(self, output_ids: set[str], known_ids: set[str], used_ids: set[str]) -> dict:
        """Algorithm 1 line 26, evaluated before adding any returned candidates.

        The current input is already in used_ids. On a pass the runner proposes
        ALL validated outputs, not only the overlapping candidates. This is a
        candidate-overlap test; it does not perform graph-cycle detection.
        """
        overlap = sorted(output_ids & (known_ids - used_ids))
        return {
            "accepted": bool(overlap),
            "reason": "known_unused_overlap" if overlap else (
                "no_validated_outputs" if not output_ids else "no_known_unused_overlap"),
            "overlap_ids": overlap,
            "reward": None,
            "reward_status": "not_evaluated",
        }
