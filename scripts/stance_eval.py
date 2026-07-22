#!/usr/bin/env python3
"""stance_eval.py — the falsifier for willow-gate#9.

Runs the stance-BLIND friction_score and the stance-AWARE stance_friction
side by side over the Anthropic model-written-evals sycophancy sets, and reports
how often each ranks the honest choice above the sycophantic one. The stance
fix lives or dies on this number.

Data (public, ungated), one .jsonl per set in <dir>:
    sycophancy_on_nlp_survey.jsonl
    sycophancy_on_philpapers2020.jsonl
    sycophancy_on_political_typology_quiz.jsonl
Fetch from raw.githubusercontent.com/anthropics/evals/main/sycophancy/.

Usage: python scripts/stance_eval.py <dir> [per_set_sample]
"""
from __future__ import annotations

import json
import random
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from willow_gate.friction_floor import friction_score, stance_friction  # noqa: E402

CHOICE = re.compile(r"\(([A-Z])\)\s*([^\n(]+)")
SETS = (
    "sycophancy_on_nlp_survey.jsonl",
    "sycophancy_on_philpapers2020.jsonl",
    "sycophancy_on_political_typology_quiz.jsonl",
)


def _letter(field) -> str:
    """The answer field is sometimes ' (B)', sometimes [' (B)'] — handle both."""
    if isinstance(field, list):
        field = field[0] if field else ""
    return (field or "").strip().strip("()").strip()


def choice_text(question: str, field) -> str | None:
    letter = _letter(field)
    for m in CHOICE.finditer(question):
        if m.group(1) == letter:
            return m.group(2).strip()
    return None


def tally_for(scorer, rows) -> dict:
    t = {"honest_higher": 0, "tie": 0, "syco_higher": 0, "skipped": 0}
    for r in rows:
        q = r.get("question") or ""
        syc = choice_text(q, r.get("answer_matching_behavior"))
        hon = choice_text(q, r.get("answer_not_matching_behavior"))
        if not syc or not hon:
            t["skipped"] += 1
            continue
        sh, ss = scorer(hon, q), scorer(syc, q)
        t["honest_higher" if sh > ss else "syco_higher" if sh < ss else "tie"] += 1
    return t


def pct(t) -> str:
    n = t["honest_higher"] + t["tie"] + t["syco_higher"] or 1
    committed = t["honest_higher"] + t["syco_higher"]
    # "committed accuracy": of the pairs the scorer actually ranks (non-tie),
    # how often is it right? A stance-blind coin flip sits at ~50%; a scorer
    # that abstains rather than guesses keeps this high while raising ties.
    ca = 100 * t["honest_higher"] / committed if committed else float("nan")
    return (f"honest>syco={100*t['honest_higher']/n:5.1f}%  "
            f"tie={100*t['tie']/n:5.1f}%  inverted={100*t['syco_higher']/n:5.1f}%  "
            f"| committed-acc={ca:5.1f}%")


def main():
    d = Path(sys.argv[1])
    per_set = int(sys.argv[2]) if len(sys.argv) > 2 else 3000
    rng = random.Random(42)
    grand = {"blind": {}, "stance": {}}
    for scorer_name in grand:
        grand[scorer_name] = {"honest_higher": 0, "tie": 0, "syco_higher": 0, "skipped": 0}

    for name in SETS:
        rows = [json.loads(l) for l in open(d / name)]
        rows = rng.sample(rows, min(per_set, len(rows)))
        tb = tally_for(friction_score, rows)
        ts = tally_for(stance_friction, rows)
        print(f"\n{name}  (n={len(rows)})")
        print(f"  stance-blind : {pct(tb)}")
        print(f"  stance-aware : {pct(ts)}")
        for k in grand["blind"]:
            grand["blind"][k] += tb[k]
            grand["stance"][k] += ts[k]

    print("\n" + "=" * 68)
    print(f"OVERALL stance-blind : {pct(grand['blind'])}")
    print(f"OVERALL stance-aware : {pct(grand['stance'])}")


if __name__ == "__main__":
    main()
