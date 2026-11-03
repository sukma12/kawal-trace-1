"""Phishing Classifier Model: lightweight TF-IDF + Multinomial Naive Bayes, run offline.

Two storage formats are supported:

* ``phishing_model.json`` (default, portable): plain numbers, evaluated by the pure-Python
  code below. Loading it cannot execute code and needs no scikit-learn, so it works in the
  packaged Windows/Android app.
* ``phishing_model.pkl`` (joblib/pickle, produced by ml_models/train_model.py): pickle can run
  arbitrary code when loaded, so it is only loaded when the caller passes ``allow_pickle=True``
  AND the file's SHA-256 matches MODEL_MANIFEST.json AND scikit-learn is installed.

The model returns a probability, not a verdict. A format-2 model is an ensemble: the Naive Bayes log-odds are one
input of a small logistic stack that also weighs text/link signals (detectors/phishing_ensemble.py), and carries
its own thresholds for the SUSPICIOUS and PHISHING bands. A format-1 model (Naive Bayes only) keeps the old rule:
PHISHING at >= 70 %. A score is never presented as certainty and a missing/untrusted model is reported as
"AI unavailable" rather than silently treated as a clean result.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from .phishing_ensemble import FEATURE_LABELS, FEATURE_ORDER, extract_features
from .text_preprocess import preprocess_text

PHISHING_THRESHOLD = 0.70
MODEL_JSON_NAME = "phishing_model.json"
MODEL_PKL_NAME = "phishing_model.pkl"
MANIFEST_NAME = "MODEL_MANIFEST.json"
MAX_MODEL_BYTES = 32 * 1024 * 1024
_TOKEN_RE = re.compile(r"(?u)\b\w\w+\b")  # identical to scikit-learn's default tokenizer


class ClassifierError(Exception):
    pass


NB_LOGIT_CLIP = 12.0   # Naive Bayes log-odds are over-confident; the stack only sees them clipped to +-12


@dataclass(frozen=True)
class Prediction:
    score: float          # probability the text is phishing (0..1) from the text model alone
    known_terms: int      # how many of its terms the model has seen; 0 => inconclusive
    backend: str
    logit: float = 0.0    # log-odds behind `score` (portable backend only)


@dataclass(frozen=True)
class Assessment:
    """What the scanner shows: one probability, the band it falls in, and the signals that pushed it there."""
    score: float                                   # final probability (ensemble when the model has a stack)
    band: str                                      # PHISHING | SUSPICIOUS | SAFE | INCONCLUSIVE
    text_score: float                              # the text-only model's probability
    known_terms: int
    backend: str
    ensemble: bool
    reasons: tuple[tuple[str, float], ...] = ()    # (Indonesian label, weight in log-odds), strongest first
    thresholds: tuple[float, float] = (0.0, PHISHING_THRESHOLD)   # (suspicious, phishing)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _terms(clean_text: str, ngram_range: tuple[int, int]) -> list[str]:
    tokens = _TOKEN_RE.findall(clean_text)
    lo, hi = ngram_range
    out: list[str] = []
    for n in range(lo, hi + 1):
        if n == 1:
            out.extend(tokens)
        else:
            out.extend(" ".join(tokens[i:i + n]) for i in range(len(tokens) - n + 1))
    return out


class PortableNaiveBayes:
    """Inference for a TF-IDF (sublinear, L2) + MultinomialNB model exported as JSON."""

    backend = "portable-json"

    def __init__(self, spec: dict[str, Any]) -> None:
        try:
            if spec.get("format") != "kawaltrace-portable-nb" or int(spec.get("version", 0)) not in (1, 2):
                raise ClassifierError("Format model tidak dikenal.")
            self.ngram_range = (int(spec["ngram_range"][0]), int(spec["ngram_range"][1]))
            self.sublinear_tf = bool(spec["sublinear_tf"])
            self.prior = [float(x) for x in spec["class_log_prior"]]            # [safe, phishing]
            raw_terms = spec["terms"]                                           # term -> [idf, lp_safe, lp_phish]
            self.terms = {str(t): (float(v[0]), float(v[1]), float(v[2])) for t, v in raw_terms.items()}
            self.training = dict(spec.get("training", {}))
            self.stack = self._parse_stack(spec.get("stack"))
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise ClassifierError("Struktur model JSON tidak valid.") from exc
        if len(self.prior) != 2 or not self.terms or not 1 <= self.ngram_range[0] <= self.ngram_range[1] <= 3:
            raise ClassifierError("Isi model JSON tidak valid.")
        if not all(math.isfinite(x) for x in self.prior):
            raise ClassifierError("Prior model tidak valid.")

    @staticmethod
    def _parse_stack(raw: Any) -> dict[str, Any] | None:
        """Validate the optional logistic stack. A model that names a feature this build does not know is refused:
        silently ignoring it would change the score without anyone noticing."""
        if raw is None:
            return None
        names = [str(n) for n in raw["features"]]
        weights = [float(w) for w in raw["weights"]]
        unknown = [n for n in names if n not in FEATURE_LABELS]
        if unknown or len(names) != len(weights) or len(set(names)) != len(names):
            raise ClassifierError("Model memakai fitur yang tidak dikenal aplikasi ini: " + ", ".join(unknown[:3]))
        nb_weight, bias = float(raw["nb_weight"]), float(raw["bias"])
        low, high = float(raw["thresholds"]["suspicious"]), float(raw["thresholds"]["phishing"])
        if not all(math.isfinite(x) for x in (*weights, nb_weight, bias, low, high)) or not 0.0 < low <= high < 1.0:
            raise ClassifierError("Parameter tumpukan model tidak valid.")
        return {"weights": dict(zip(names, weights)), "nb_weight": nb_weight, "bias": bias, "thresholds": (low, high)}

    def predict(self, text: str) -> Prediction:
        counts = Counter(t for t in _terms(preprocess_text(text), self.ngram_range) if t in self.terms)
        weights: dict[str, float] = {}
        for term, count in counts.items():
            tf = 1.0 + math.log(count) if self.sublinear_tf else float(count)
            weights[term] = tf * self.terms[term][0]
        norm = math.sqrt(sum(w * w for w in weights.values()))
        joint = list(self.prior)
        if norm > 0:
            for term, weight in weights.items():
                x = weight / norm
                joint[0] += x * self.terms[term][1]
                joint[1] += x * self.terms[term][2]
        peak = max(joint)
        exps = [math.exp(j - peak) for j in joint]
        return Prediction(exps[1] / sum(exps), len(weights), self.backend, joint[1] - joint[0])

    def assess(self, text: str, links: Sequence[tuple[str, bool]] = ()) -> Assessment:
        """Ensemble score. `links` = [(url, display_text_names_another_site)] as found by the link extractor."""
        base = self.predict(text)
        if self.stack is None:
            band = "INCONCLUSIVE" if base.known_terms == 0 else "PHISHING" if base.score >= PHISHING_THRESHOLD else "SAFE"
            return Assessment(base.score, band, base.score, base.known_terms, self.backend, False, (), (0.0, PHISHING_THRESHOLD))
        feats = extract_features(text, links)
        low, high = self.stack["thresholds"]
        clipped = max(-NB_LOGIT_CLIP, min(NB_LOGIT_CLIP, base.logit))
        contributions = {n: w * feats[n] for n, w in self.stack["weights"].items() if feats.get(n, 0.0)}
        z = self.stack["bias"] + self.stack["nb_weight"] * clipped + sum(contributions.values())
        score = 1.0 / (1.0 + math.exp(-max(-60.0, min(60.0, z))))
        reasons = [(FEATURE_LABELS[n], round(c, 2)) for n, c in sorted(contributions.items(), key=lambda kv: -kv[1]) if c >= 0.4]
        if self.stack["nb_weight"] * clipped >= 0.4:
            reasons.append(("kata-kata dalam pesan mirip contoh phishing yang dikenal model", round(self.stack["nb_weight"] * clipped, 2)))
            reasons.sort(key=lambda r: -r[1])
        if base.known_terms == 0 and not contributions:
            band = "INCONCLUSIVE"
        else:
            band = "PHISHING" if score >= high else "SUSPICIOUS" if score >= low else "SAFE"
        return Assessment(score, band, base.score, base.known_terms, self.backend, True, tuple(reasons[:5]), (low, high))


class SklearnPickleModel:
    backend = "sklearn-pickle"

    def __init__(self, pipeline: Any) -> None:
        self.pipeline = pipeline

    def predict(self, text: str) -> Prediction:
        clean = preprocess_text(text)
        score = float(self.pipeline.predict_proba([clean])[0][1])
        return Prediction(score, -1, self.backend)


class PhishingClassifier:
    """Facade used by the scanner pipeline."""

    def __init__(self, model: Any | None, status: str) -> None:
        self.model = model
        self.status = status

    @property
    def available(self) -> bool:
        return self.model is not None

    def predict(self, text: str) -> Prediction | None:
        return self.model.predict(text) if self.model is not None else None

    def assess(self, text: str, links: Sequence[tuple[str, bool]] = ()) -> Assessment | None:
        if self.model is None:
            return None
        if hasattr(self.model, "assess"):
            return self.model.assess(text, links)
        base = self.model.predict(text)        # pickle backend: text model only
        return Assessment(base.score, "PHISHING" if base.score >= PHISHING_THRESHOLD else "SAFE", base.score,
                          base.known_terms, base.backend, False, (), (0.0, PHISHING_THRESHOLD))

    @classmethod
    def load(cls, model_dir: str | Path, *, allow_pickle: bool = False) -> "PhishingClassifier":
        directory = Path(model_dir)
        manifest: dict[str, str] = {}
        try:
            loaded = json.loads((directory / MANIFEST_NAME).read_text(encoding="utf-8"))
            manifest = {str(k): str(v).lower() for k, v in dict(loaded.get("sha256", {})).items()}
        except (OSError, ValueError, AttributeError):
            manifest = {}

        json_path = directory / MODEL_JSON_NAME
        if json_path.is_file():
            try:
                if json_path.stat().st_size > MAX_MODEL_BYTES:
                    return cls(None, "Model AI ditolak: ukuran file melebihi batas.")
                if manifest.get(MODEL_JSON_NAME) and sha256_file(json_path) != manifest[MODEL_JSON_NAME]:
                    return cls(None, "Model AI ditolak: checksum tidak cocok dengan MODEL_MANIFEST.json (file diubah/rusak).")
                spec = json.loads(json_path.read_text(encoding="utf-8"))
                return cls(PortableNaiveBayes(spec), "Model AI portable siap (offline).")
            except (OSError, ValueError, ClassifierError) as exc:
                return cls(None, f"Model AI tidak dapat dimuat: {type(exc).__name__}.")

        pkl_path = directory / MODEL_PKL_NAME
        if allow_pickle and pkl_path.is_file():
            expected = manifest.get(MODEL_PKL_NAME)
            if not expected:
                return cls(None, "Model .pkl ditolak: tidak ada checksum di MODEL_MANIFEST.json.")
            try:
                if sha256_file(pkl_path) != expected:
                    return cls(None, "Model .pkl ditolak: checksum tidak cocok.")
                import joblib  # type: ignore
                return cls(SklearnPickleModel(joblib.load(pkl_path)), "Model .pkl terverifikasi dimuat.")
            except ImportError:
                return cls(None, "Model .pkl butuh scikit-learn/joblib yang tidak terpasang.")
            except Exception as exc:  # noqa: BLE001 - never let a bad model crash a scan
                return cls(None, f"Model .pkl gagal dimuat: {type(exc).__name__}.")
        return cls(None, "Model AI tidak ditemukan; pemindaian teks memakai blacklist saja.")
