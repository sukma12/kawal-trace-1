"""Train and honestly evaluate the phishing ensemble (development machine only; needs scikit-learn).

    python -m ml_models.train_model                 # hand-written corpus (ml_models/corpus_seed.py)
    python -m ml_models.train_model --data my.csv   # your own data: columns text,label[,group]  (1=phishing, 0=safe)
    python -m ml_models.train_model --no-eval       # skip the cross-validation (fast; writes no evaluation)

What it builds (next to this file):
  phishing_model.json  portable format-2 model: TF-IDF + Naive Bayes weights, logistic stack, thresholds.
                       The app reads ONLY this file (no scikit-learn, nothing executable).
  MODEL_MANIFEST.json  SHA-256 of the model + training metadata; the app refuses a model whose hash differs.
  EVALUATION.json      every number reported in docs/AI_MODEL.md, with the model hash it belongs to.
  phishing_model.pkl   only with --with-pickle: a scikit-learn pipeline for developers (pickle can run code).

How the numbers are produced (the point of this file):
* Leave-one-GROUP-out: each scam / mail family is held out in turn and scored by a model that never saw it, through
  the SAME code the app runs (detectors.phishing_classifier). A score is "how well does it handle a new kind of
  message", not "does it remember its templates".
* The stack's inputs for its own training rows are out-of-fold Naive Bayes scores, so it is never fed scores from a
  model that had memorised those rows.
* Thresholds are picked from the out-of-fold scores of the seed corpus only. The challenge set is never used for
  fitting or selecting anything.
* The older template-trained model is evaluated on the same data as a baseline.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from detectors.link_extractor import extract_links  # noqa: E402
from detectors.phishing_classifier import (  # noqa: E402
    MANIFEST_NAME, MODEL_JSON_NAME, MODEL_PKL_NAME, NB_LOGIT_CLIP, PHISHING_THRESHOLD, PortableNaiveBayes, sha256_file,
)
from detectors.phishing_ensemble import FEATURE_ORDER, extract_features  # noqa: E402
from detectors.text_preprocess import preprocess_text  # noqa: E402

EVALUATION_NAME = "EVALUATION.json"
LEGIT_FPR_PHISHING = 0.02       # the PHISHING band may wrongly flag at most ~2 % of legitimate seed messages
LEGIT_FPR_SUSPICIOUS = 0.10     # the SUSPICIOUS band at most ~10 %
STACK_C = 1.0                   # fixed, not tuned
# HAND-SET minimum weights (log-odds), from domain knowledge rather than from the data: these signals are rare in a small
# corpus (so learning under-weights them) but are strong indicators in practice. Learning may raise them, never lower.
# Installing an .apk sent in a message is the dominant malware route against Indonesian users.
PRIOR_FLOOR = {"display_mismatch": 2.0, "url_hi": 1.5, "url_shortener": 1.0, "apk_install": 2.5}

Row = tuple[str, int, str]      # (group, label, text)


# ------------------------------------------------------------------------------------------------ data
def load_csv(path: Path) -> list[Row]:
    rows: list[Row] = []
    with path.open(newline="", encoding="utf-8") as handle:
        for index, record in enumerate(csv.DictReader(handle)):
            label = str(record.get("label", "")).strip().lower()
            group = str(record.get("group") or "").strip() or f"pseudo-{index % 10}"
            if label in {"1", "phishing", "spam"}:
                rows.append((group, 1, record["text"]))
            elif label in {"0", "safe", "ham", "legit"}:
                rows.append((group, 0, record["text"]))
    return rows


_FEATURE_CACHE: dict[str, dict[str, float]] = {}
_LINK_CACHE: dict[str, list[tuple[str, bool]]] = {}


def links_of(text: str) -> list[tuple[str, bool]]:
    """Exactly how the scanner derives links from a pasted message."""
    cached = _LINK_CACHE.get(text)
    if cached is None:
        cached = [(l.url, l.display_mismatch) for l in extract_links(text=text, html=text if "<" in text else "")]
        _LINK_CACHE[text] = cached
    return cached


def features_of(text: str) -> dict[str, float]:
    cached = _FEATURE_CACHE.get(text)
    if cached is None:
        cached = extract_features(text, links_of(text))
        _FEATURE_CACHE[text] = cached
    return cached


# ------------------------------------------------------------------------------------------------ fitting
def _sklearn():
    try:
        import numpy as np
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.model_selection import GroupKFold
        from sklearn.naive_bayes import MultinomialNB
        from sklearn.pipeline import Pipeline
    except ImportError as exc:
        raise SystemExit("Butuh scikit-learn: pip install scikit-learn joblib numpy") from exc
    return np, TfidfVectorizer, LogisticRegression, GroupKFold, MultinomialNB, Pipeline


def fit_nb(texts: Sequence[str], labels: Sequence[int], weights: Sequence[float] | None = None):
    np, TfidfVectorizer, _, _, MultinomialNB, _ = _sklearn()
    vec = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True)
    matrix = vec.fit_transform([preprocess_text(t) for t in texts])
    nb = MultinomialNB(alpha=0.5)
    nb.fit(matrix, list(labels), sample_weight=None if weights is None else np.asarray(weights, dtype=float))
    return vec, nb


def nb_logits(vec, nb, texts: Sequence[str]) -> list[float]:
    log_proba = nb.predict_log_proba(vec.transform([preprocess_text(t) for t in texts]))
    return [float(row[1] - row[0]) for row in log_proba]


def nb_terms(vec, nb) -> dict[str, list[float]]:
    return {term: [float(vec.idf_[idx]), float(nb.feature_log_prob_[0][idx]), float(nb.feature_log_prob_[1][idx])]
            for term, idx in vec.vocabulary_.items()}


def build_spec(vec, nb, stack: dict[str, Any] | None, training: dict[str, Any]) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "format": "kawaltrace-portable-nb", "version": 2 if stack else 1, "algorithm": "tfidf+multinomial_nb" + ("+logistic_stack" if stack else ""),
        "ngram_range": list(vec.ngram_range), "sublinear_tf": bool(vec.sublinear_tf),
        "class_log_prior": [float(x) for x in nb.class_log_prior_], "terms": nb_terms(vec, nb), "training": training,
    }
    if stack:
        spec["stack"] = stack
    return spec


def fit_stack(rows: Sequence[Row], template: Sequence[tuple[str, int]], template_weight: float,
              feature_names: Sequence[str], use_nb: bool, thresholds: tuple[float, float] = (0.35, 0.65)) -> tuple[Any, Any, dict[str, Any]]:
    """Fit Naive Bayes (+ optional template data) and the logistic stack. Returns (vectorizer, nb, stack-dict)."""
    np, _, LogisticRegression, GroupKFold, _, _ = _sklearn()
    texts = [t for _, _, t in rows]
    labels = [l for _, l, _ in rows]
    groups = [g for g, _, _ in rows]
    tpl_texts = [t for t, _ in template] if template_weight > 0 else []
    tpl_labels = [l for _, l in template] if template_weight > 0 else []

    def nb_for(idx: Sequence[int]):
        return fit_nb([texts[i] for i in idx] + tpl_texts, [labels[i] for i in idx] + tpl_labels,
                      [1.0] * len(idx) + [template_weight] * len(tpl_texts))

    final_vec, final_nb = nb_for(range(len(rows)))
    oof = [0.0] * len(rows)
    if use_nb:
        n_splits = max(2, min(5, len(set(groups))))
        for train_idx, val_idx in GroupKFold(n_splits=n_splits).split(texts, labels, groups):
            vec, nb = nb_for(list(train_idx))
            for i, value in zip(val_idx, nb_logits(vec, nb, [texts[j] for j in val_idx])):
                oof[int(i)] = value
    design = [([max(-NB_LOGIT_CLIP, min(NB_LOGIT_CLIP, oof[i]))] if use_nb else []) + [features_of(texts[i])[f] for f in feature_names]
              for i in range(len(rows))]
    model = LogisticRegression(C=STACK_C, class_weight="balanced", max_iter=2000)
    model.fit(np.asarray(design, dtype=float), labels)
    coef = [float(c) for c in model.coef_[0]]
    nb_weight = coef[0] if use_nb else 0.0
    weights = dict(zip(feature_names, coef[1:] if use_nb else coef))
    source: dict[str, str] = {}
    for name in feature_names:
        if name in PRIOR_FLOOR and weights[name] < PRIOR_FLOOR[name]:
            source[name] = f"batas bawah tulisan tangan {PRIOR_FLOOR[name]} (hasil belajar {weights[name]:.2f})"
            weights[name] = PRIOR_FLOOR[name]
    stack = {"features": list(weights), "weights": [weights[n] for n in weights], "nb_weight": nb_weight,
             "bias": float(model.intercept_[0]), "thresholds": {"suspicious": thresholds[0], "phishing": thresholds[1]},
             "use_text_model": use_nb, "weight_source": source}
    return final_vec, final_nb, stack


def score_with(spec: dict[str, Any], texts: Sequence[str]) -> list[float]:
    """Score through the runtime code path (the same one the scanner calls)."""
    model = PortableNaiveBayes(spec)
    return [model.assess(t, links_of(t)).score for t in texts]


# ------------------------------------------------------------------------------------------------ evaluation
def wilson(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 1.0)
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def pick_thresholds(scores: Sequence[float], labels: Sequence[int]) -> tuple[float, float]:
    """Lowest thresholds whose false-positive rate on LEGITIMATE out-of-fold scores stays within the targets."""
    legit = sorted(s for s, l in zip(scores, labels) if l == 0)

    def lowest(target: float) -> float:
        allowed = int(math.floor(target * len(legit)))
        cutoff = legit[-(allowed + 1)] if allowed < len(legit) else 0.0     # the (allowed+1)-th highest legit score must stay below
        return min(0.99, max(cutoff + 1e-6, 0.05))

    high = lowest(LEGIT_FPR_PHISHING)
    low = min(lowest(LEGIT_FPR_SUSPICIOUS), high)
    return (round(low, 4), round(max(high, low), 4))


def summarise(scores: Sequence[float], labels: Sequence[int], groups: Sequence[str], thresholds: tuple[float, float]) -> dict[str, Any]:
    from sklearn.metrics import roc_auc_score
    low, high = thresholds
    pos = [s for s, l in zip(scores, labels) if l == 1]
    neg = [s for s, l in zip(scores, labels) if l == 0]
    tp = sum(1 for s in pos if s >= high)
    fp = sum(1 for s in neg if s >= high)
    flagged_pos = sum(1 for s in pos if s >= low)
    flagged_neg = sum(1 for s in neg if s >= low)
    per_group: dict[str, dict[str, Any]] = {}
    for g in sorted(set(groups)):
        member = [(s, l) for s, l, gg in zip(scores, labels, groups) if gg == g]
        label = member[0][1]
        per_group[g] = {"label": label, "n": len(member),
                        "flagged_phishing": sum(1 for s, _ in member if s >= high) / len(member),
                        "flagged_at_least_suspicious": sum(1 for s, _ in member if s >= low) / len(member)}
    return {
        "n_phishing": len(pos), "n_legit": len(neg), "auc": round(float(roc_auc_score(labels, scores)), 4),
        "thresholds": {"suspicious": low, "phishing": high},
        "phishing_band": {"recall": round(tp / len(pos), 4), "recall_ci95": [round(x, 4) for x in wilson(tp, len(pos))],
                          "false_positive_rate": round(fp / len(neg), 4), "fpr_ci95": [round(x, 4) for x in wilson(fp, len(neg))],
                          "precision": round(tp / (tp + fp), 4) if tp + fp else None},
        "at_least_suspicious": {"recall": round(flagged_pos / len(pos), 4), "recall_ci95": [round(x, 4) for x in wilson(flagged_pos, len(pos))],
                                "false_positive_rate": round(flagged_neg / len(neg), 4), "fpr_ci95": [round(x, 4) for x in wilson(flagged_neg, len(neg))]},
        "per_group": per_group,
    }


def leave_one_group_out(rows: Sequence[Row], template: Sequence[tuple[str, int]], cfg: dict[str, Any]) -> list[float]:
    scores = [0.0] * len(rows)
    for held in sorted({g for g, _, _ in rows}):
        train = [r for r in rows if r[0] != held]
        vec, nb, stack = fit_stack(train, template, cfg["template_weight"], cfg["features"], cfg["use_nb"])
        spec = build_spec(vec, nb, stack, {})
        idx = [i for i, r in enumerate(rows) if r[0] == held]
        for i, value in zip(idx, score_with(spec, [rows[i][2] for i in idx])):
            scores[i] = value
    return scores


VARIANTS: dict[str, dict[str, Any]] = {
    "naive_bayes_only": {"features": [], "use_nb": True, "template_weight": 0.0,
                         "about": "hanya skor teks Naive Bayes (dikalibrasi), tanpa sinyal tautan/teks"},
    "signals_only": {"features": list(FEATURE_ORDER), "use_nb": False, "template_weight": 0.0,
                     "about": "hanya sinyal tautan/teks, tanpa Naive Bayes"},
    "ensemble": {"features": list(FEATURE_ORDER), "use_nb": True, "template_weight": 0.0,
                 "about": "ensemble: Naive Bayes + sinyal, korpus tulisan tangan saja"},
    "ensemble_plus_templates": {"features": list(FEATURE_ORDER), "use_nb": True, "template_weight": 0.25,
                                "about": "ensemble + 800 contoh templat sintetis berbobot 0,25 untuk Naive Bayes"},
}


def evaluate(seed: Sequence[Row], challenge: Sequence[Row], template: Sequence[tuple[str, int]]) -> dict[str, Any]:
    labels = [l for _, l, _ in seed]
    groups = [g for g, _, _ in seed]
    c_labels = [l for _, l, _ in challenge]
    c_groups = [g for g, _, _ in challenge]
    report: dict[str, Any] = {"variants": {}}
    for name, cfg in VARIANTS.items():
        oof = leave_one_group_out(seed, template, cfg)
        thresholds = pick_thresholds(oof, labels)
        vec, nb, stack = fit_stack(seed, template, cfg["template_weight"], cfg["features"], cfg["use_nb"], thresholds)
        spec = build_spec(vec, nb, stack, {})
        challenge_scores = score_with(spec, [t for _, _, t in challenge])
        report["variants"][name] = {"about": cfg["about"], "leave_one_group_out": summarise(oof, labels, groups, thresholds),
                                    "challenge_set": summarise(challenge_scores, c_labels, c_groups, thresholds)}
    # baseline: the model the project shipped before (Naive Bayes on the 800-sample template corpus, PHISHING at 0.70)
    tpl_vec, tpl_nb = fit_nb([t for t, _ in template], [l for _, l in template])
    baseline = build_spec(tpl_vec, tpl_nb, None, {})
    fixed = (PHISHING_THRESHOLD, PHISHING_THRESHOLD)
    report["baseline_template_model"] = {
        "about": "model lama: Naive Bayes pada korpus templat sintetis, PHISHING bila skor >= 0,70 (tidak pernah melihat data di atas)",
        "seed_corpus": summarise(score_with(baseline, [t for _, _, t in seed]), labels, groups, fixed),
        "challenge_set": summarise(score_with(baseline, [t for _, _, t in challenge]), c_labels, c_groups, fixed)}
    # pre-registered choice: the ensemble variant with the higher leave-one-group-out AUC
    candidates = ("ensemble", "ensemble_plus_templates")
    report["chosen"] = max(candidates, key=lambda n: report["variants"][n]["leave_one_group_out"]["auc"])
    return report


# ------------------------------------------------------------------------------------------------ main
def render_markdown(report: dict[str, Any]) -> str:
    def pct(x: float) -> str:
        return f"{x * 100:.1f}%"

    def line(name: str, block: dict[str, Any]) -> str:
        p, s = block["phishing_band"], block["at_least_suspicious"]
        return (f"| {name} | {block['auc']:.3f} | {pct(p['recall'])} ({pct(p['recall_ci95'][0])}-{pct(p['recall_ci95'][1])}) | "
                f"{pct(p['false_positive_rate'])} | {pct(s['recall'])} | {pct(s['false_positive_rate'])} |")
    out = ["| Varian | AUC | Recall PHISHING (95% CI) | FPR PHISHING | Recall >= MENCURIGAKAN | FPR >= MENCURIGAKAN |", "|---|---|---|---|---|---|"]
    for title, key in (("Leave-one-group-out (korpus seed)", "leave_one_group_out"), ("Set tantangan (skenario baru)", "challenge_set")):
        out.append(f"| **{title}** | | | | | |")
        for name, data in report["variants"].items():
            out.append(line(("-> " if name == report["chosen"] else "") + name, data[key]))
    base = report["baseline_template_model"]
    out.append("| **Model lama (templat), ambang 0,70** | | | | | |")
    out.append(line("lama pada korpus seed", base["seed_corpus"]))
    out.append(line("lama pada set tantangan", base["challenge_set"]))
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data", type=Path, help="CSV dengan kolom text,label[,group]")
    parser.add_argument("--out", type=Path, default=HERE)
    parser.add_argument("--no-eval", action="store_true", help="lewati validasi silang (cepat; tidak menulis EVALUATION.json)")
    parser.add_argument("--with-pickle", action="store_true", help="tulis juga phishing_model.pkl (khusus developer)")
    args = parser.parse_args(argv)

    from ml_models.corpus_challenge import challenge_rows
    from ml_models.corpus_seed import seed_rows
    from ml_models.training_corpus import build_corpus

    template = build_corpus()
    if args.data:
        seed, challenge, source = load_csv(args.data), [], f"csv:{args.data.name}"
    else:
        seed, challenge, source = seed_rows(), challenge_rows(), "hand-written corpus (ml_models/corpus_seed.py)"
    if len({l for _, l, _ in seed}) != 2 or len(seed) < 40:
        raise SystemExit("Data latih harus memuat kedua kelas dan minimal 40 contoh.")
    args.out.mkdir(parents=True, exist_ok=True)

    report: dict[str, Any] = {}
    chosen = VARIANTS["ensemble"]
    chosen_name = "ensemble"
    thresholds = (0.35, 0.65)
    if not args.no_eval and challenge:
        report = evaluate(seed, challenge, template)
        chosen_name = report["chosen"]
        chosen = VARIANTS[chosen_name]
        block = report["variants"][chosen_name]["leave_one_group_out"]["thresholds"]
        thresholds = (block["suspicious"], block["phishing"])
    elif not args.no_eval:
        labels = [l for _, l, _ in seed]
        oof = leave_one_group_out(seed, template, chosen)
        thresholds = pick_thresholds(oof, labels)
        report = {"variants": {"ensemble": {"leave_one_group_out": summarise(oof, labels, [g for g, _, _ in seed], thresholds)}}, "chosen": "ensemble"}

    vec, nb, stack = fit_stack(seed, template, chosen["template_weight"], chosen["features"], chosen["use_nb"], thresholds)
    training = {"samples": len(seed), "groups": len({g for g, _, _ in seed}), "source": source, "variant": chosen_name,
                "template_weight": chosen["template_weight"], "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "evaluation": "lihat EVALUATION.json dan docs/AI_MODEL.md; angka tidak diulang di sini agar tidak basi"}
    spec = build_spec(vec, nb, stack, training)
    model_path = args.out / MODEL_JSON_NAME
    model_path.write_text(json.dumps(spec, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    manifest: dict[str, Any] = {"sha256": {MODEL_JSON_NAME: sha256_file(model_path)}, "training": training}
    if args.with_pickle:
        import joblib
        from sklearn.pipeline import Pipeline
        pipeline = Pipeline([("tfidf", vec), ("nb", nb)])
        joblib.dump(pipeline, args.out / MODEL_PKL_NAME, compress=3)
        manifest["sha256"][MODEL_PKL_NAME] = sha256_file(args.out / MODEL_PKL_NAME)
    (args.out / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if report:
        report["model_sha256"] = manifest["sha256"][MODEL_JSON_NAME]
        report["corpus"] = {"seed_rows": len(seed), "seed_groups": len({g for g, _, _ in seed}), "challenge_rows": len(challenge),
                            "template_rows": len(template), "source": source}
        report["generated_utc"] = training["trained_at"]
        (args.out / EVALUATION_NAME).write_text(json.dumps(report, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        if "baseline_template_model" in report:
            print(render_markdown(report))
    print(json.dumps({"model": str(model_path), "thresholds": {"suspicious": thresholds[0], "phishing": thresholds[1]},
                      "sha256": manifest["sha256"][MODEL_JSON_NAME]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
