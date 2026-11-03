"""The phishing ensemble: feature rules, model loading, scanner behaviour, and the integrity of the shipped evaluation.

These tests pin BEHAVIOUR (what is flagged and why). They do not prove the model is accurate on real mail: the
accuracy numbers live in ml_models/EVALUATION.json and docs/AI_MODEL.md together with their limits.
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path

import pytest

from detectors.phishing_classifier import MODEL_JSON_NAME, PhishingClassifier
from detectors.phishing_ensemble import FEATURE_LABELS, FEATURE_ORDER, extract_features
from detectors.pipeline import SecurityScanner

ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT / "ml_models"
sys.path.insert(0, str(ROOT))


def feats(text, links=()):
    return extract_features(text, list(links))


# ------------------------------------------------------------------------------------------- feature rules
def test_credential_request_fires_on_the_ask_but_not_on_an_official_warning():
    ask = feats("Segera masukkan kata sandi dan kode OTP Anda untuk verifikasi")
    assert ask["cred_request"] == 1.0
    warning = feats("Kode OTP Anda adalah 482913. JANGAN BERIKAN kode ini kepada siapa pun.")
    assert warning["cred_request"] == 0.0 and warning["otp_warning"] == 1.0
    english = feats("Never share this code with anyone. We will never ask you for it.")
    assert english["otp_warning"] == 1.0 and english["cred_request"] == 0.0


def test_words_inside_a_link_do_not_trigger_the_text_rules():
    quiet = feats("Lihat catatan rapat di sini: http://verify-password-otp-now.example.org/login")
    assert quiet["cred_request"] == 0.0 and quiet["urgency"] == 0.0


def test_apk_requests_and_chat_channel_requests_are_recognised():
    assert feats("Silakan unduh file FOTO_KEGIATAN.apk lalu install")["apk_install"] == 1.0
    assert feats("photos_viewer.apk then allow all permissions")["apk_install"] == 1.0
    assert feats("Please read the attached notes")["apk_install"] == 0.0
    assert feats("Chat WhatsApp 0838 1100 2244 untuk gabung")["contact_channel"] == 1.0
    assert feats("Message our HR on Telegram @hr_global_jobs")["contact_channel"] == 1.0


def test_link_features_separate_a_lookalike_host_from_the_services_own_domain():
    lookalike = feats("Akun BCA Anda diblokir", [("http://bca-secure-verify.top/login", False)])
    assert lookalike["brand_lookalike"] == 1.0 and lookalike["kw_host"] == 1.0 and lookalike["risky_tld"] == 1.0
    assert lookalike["host_hyphens"] == 1.0 and lookalike["url_http"] == 1.0 and lookalike["has_url"] == 1.0
    # real services whose own hostnames contain the very words the rule looks for
    for url in ("https://support.google.com/accounts/answer/1", "https://login.microsoftonline.com/common/oauth2", "http://www.bca.co.id/id"):
        official = feats("Anda meminta reset kata sandi.", [(url, False)])
        for name in ("kw_host", "risky_tld", "host_hyphens", "url_http", "brand_lookalike"):
            assert official[name] == 0.0, (url, name)
        assert official["has_url"] == 1.0
    # the same words on a host that is NOT theirs do count
    assert feats("x", [("https://support-google-help.top/a", False)])["kw_host"] == 1.0
    assert feats("x", [("https://login.microsoftonline.com.evil-site.top/a", False)])["kw_host"] == 1.0


def test_brand_mismatch_needs_a_brand_in_the_text_and_no_link_to_that_brands_own_domain():
    other = feats("Akun BCA Anda perlu diperbarui", [("https://toko-sepatu.example.com/x", False)])
    assert other["brand_mismatch"] == 1.0
    own = feats("Akun BCA Anda perlu diperbarui", [("https://www.bca.co.id/id/informasi", False)])
    assert own["brand_mismatch"] == 0.0
    both = feats("Akun BCA Anda", [("https://toko-sepatu.example.com/x", False), ("https://www.bca.co.id/id", False)])
    assert both["brand_mismatch"] == 0.0
    assert feats("Rapat besok pukul 9", [("https://toko-sepatu.example.com/x", False)])["brand_mismatch"] == 0.0


def test_display_text_mismatch_and_bare_shorteners_and_abused_hosting():
    assert feats("klik", [("https://evil.example.top/a", True)])["display_mismatch"] == 1.0
    assert feats("klik", [("https://evil.example.top/a", False)])["display_mismatch"] == 0.0
    assert feats("Pay now at tinyurl.com/pkg-release-88")["url_shortener"] == 1.0
    assert feats("isi di sini", [("https://sites.google.com/view/x", False)])["hosting_abuse"] == 1.0
    assert feats("isi di sini", [("https://www.tokopedia.com/x", False)])["hosting_abuse"] == 0.0


def test_features_are_bounded_deterministic_and_fast_on_hostile_input():
    hostile = ("a " * 200_000) + "http://" + "a." * 5000 + "com " + "<" * 50_000
    start = time.perf_counter()
    first, second = feats(hostile), feats(hostile)
    assert time.perf_counter() - start < 5
    assert first == second and set(first) == set(FEATURE_ORDER)
    assert all(0.0 <= v <= 1.0 for v in first.values())
    assert set(FEATURE_LABELS) == set(FEATURE_ORDER)


# ------------------------------------------------------------------------------------------- model loading
def _model_copy(tmp_path, mutate=None, drop_stack=False, version=None):
    spec = json.loads((MODEL_DIR / MODEL_JSON_NAME).read_text(encoding="utf-8"))
    if drop_stack:
        spec.pop("stack")
        spec["version"] = 1
    if version is not None:
        spec["version"] = version
    if mutate:
        mutate(spec)
    (tmp_path / MODEL_JSON_NAME).write_text(json.dumps(spec), encoding="utf-8")      # no manifest: nothing to check against
    return PhishingClassifier.load(tmp_path)


def test_shipped_model_is_an_ensemble_with_bands_and_documented_hand_set_floors():
    spec = json.loads((MODEL_DIR / MODEL_JSON_NAME).read_text(encoding="utf-8"))
    stack = spec["stack"]
    assert spec["version"] == 2 and 0 < stack["thresholds"]["suspicious"] <= stack["thresholds"]["phishing"] < 1
    assert set(stack["features"]) <= set(FEATURE_ORDER)
    assert stack["weight_source"], "hand-set weights must stay visible in the model file"
    assert all("batas bawah tulisan tangan" in note for note in stack["weight_source"].values())


def test_a_format_1_model_still_loads_and_keeps_the_old_70_percent_rule(tmp_path):
    clf = _model_copy(tmp_path, drop_stack=True)
    assert clf.available
    result = clf.assess("Your account is suspended. Verify your password immediately")
    assert result.ensemble is False and result.thresholds[1] == 0.70 and result.reasons == ()


def test_model_naming_a_feature_this_build_does_not_know_is_refused(tmp_path):
    def mutate(spec):
        spec["stack"]["features"].append("telepathy")
        spec["stack"]["weights"].append(9.0)
    clf = _model_copy(tmp_path, mutate)
    assert not clf.available and "tidak dapat dimuat" in clf.status


@pytest.mark.parametrize("change", [
    lambda s: s["stack"]["thresholds"].update(suspicious=0.9, phishing=0.5),
    lambda s: s["stack"]["thresholds"].update(phishing=1.5),
    lambda s: s["stack"].update(bias=float("nan")),
    lambda s: s["stack"].update(weights=s["stack"]["weights"][:-1]),
])
def test_malformed_stack_parameters_are_refused(tmp_path, change):
    assert not _model_copy(tmp_path, change).available


# ------------------------------------------------------------------------------------------- scanner behaviour
@pytest.fixture
def scanner(tmp_path):
    instance = SecurityScanner(tmp_path / "data")
    yield instance
    instance.close()


def test_scanner_reports_phishing_with_reasons_and_calls_it_an_estimate(scanner):
    report = scanner.scan_text("Segera masukkan PIN dan kode OTP Anda di http://bca-secure-verify.top/login atau akun diblokir")
    assert report.status == "PHISHING" and report.ai_score >= 0.7
    detail = next(d for t, d in report.findings if t == "AI_DETECTION")
    assert "Alasan:" in detail and "bukan bukti" in detail and "meminta Anda memasukkan" in detail


def test_scanner_does_not_flag_a_genuine_otp_notice_or_ordinary_mail(scanner):
    for text in ("Kode OTP Anda adalah 482913. Berlaku 5 menit. JANGAN BERIKAN kode ini kepada siapa pun.",
                 "Hi team, the weekly sync is moved to Thursday 10:00. Agenda is in the shared drive.",
                 "Backup harian selesai pukul 02:10. Ukuran 3,2 GB, status: sukses."):
        report = scanner.scan_text(text)
        assert report.status == "SAFE", (text, report.findings)


def test_the_middle_band_reports_suspicious_not_phishing(scanner):
    scanner.classifier.model.stack["thresholds"] = (0.0001, 0.9999)          # force every scored text into the middle band
    report = scanner.scan_text("Hi team, the weekly sync is moved to Thursday 10:00.")
    assert report.status == "SUSPICIOUS"
    assert any(t == "AI_DETECTION" and "mencurigakan" in d and "Periksa manual" in d for t, d in report.findings)
    assert "perlu diperiksa manual" in report.summary


def test_html_anchor_text_that_names_another_site_is_weighed(scanner):
    benign = '<p>Lihat <a href="https://www.tokopedia.com/order">status pesanan</a> Anda.</p>'
    deceptive = '<p>Verifikasi sekarang di <a href="http://bri-token-update.xyz/m">www.bri.co.id</a> dan masukkan PIN serta OTP.</p>'
    assert scanner.scan_text(benign).status == "SAFE"
    report = scanner.scan_text(deceptive)
    assert report.status == "PHISHING"
    assert any(t == "URL_HEURISTIC" for t, _ in report.findings)


# ------------------------------------------------------------------------------------------- evaluation integrity
def test_corpora_are_well_formed_and_do_not_leak_into_each_other():
    from ml_models.corpus_challenge import challenge_rows
    from ml_models.corpus_seed import seed_rows
    seed, challenge = seed_rows(), challenge_rows()
    assert {l for _, l, _ in seed} == {0, 1} and {l for _, l, _ in challenge} == {0, 1}
    texts = [t for _, _, t in seed]
    assert len(texts) == len(set(texts)), "duplicate seed message"
    assert not {t for _, _, t in challenge} & set(texts), "a challenge message also appears in the seed corpus"
    seed_groups, challenge_groups = {g for g, _, _ in seed}, {g for g, _, _ in challenge}
    assert not seed_groups & challenge_groups, "challenge scenarios must not reuse seed groups"
    for rows in (seed, challenge):
        by_group: dict[str, set[int]] = {}
        for g, l, _ in rows:
            by_group.setdefault(g, set()).add(l)
        assert all(len(v) == 1 for v in by_group.values()), "a group mixes phishing and legitimate messages"
    assert len(seed_groups) >= 20


def test_committed_evaluation_belongs_to_the_shipped_model_and_corpus():
    from ml_models.corpus_challenge import challenge_rows
    from ml_models.corpus_seed import seed_rows
    report = json.loads((MODEL_DIR / "EVALUATION.json").read_text(encoding="utf-8"))
    manifest = json.loads((MODEL_DIR / "MODEL_MANIFEST.json").read_text(encoding="utf-8"))
    model_hash = hashlib.sha256((MODEL_DIR / MODEL_JSON_NAME).read_bytes()).hexdigest()
    assert report["model_sha256"] == manifest["sha256"][MODEL_JSON_NAME] == model_hash, "evaluation is stale: retrain and re-evaluate"
    assert report["corpus"]["seed_rows"] == len(seed_rows()) and report["corpus"]["challenge_rows"] == len(challenge_rows())
    assert report["chosen"] in report["variants"]


def test_evaluation_numbers_are_honest_not_perfect_and_clear_a_sanity_floor():
    """Floors catch a broken retrain. They are NOT accuracy claims; see docs/AI_MODEL.md for what the numbers mean."""
    report = json.loads((MODEL_DIR / "EVALUATION.json").read_text(encoding="utf-8"))
    logo = report["variants"][report["chosen"]]["leave_one_group_out"]
    challenge = report["variants"][report["chosen"]]["challenge_set"]
    assert logo["auc"] >= 0.90 and challenge["auc"] >= 0.90
    assert logo["phishing_band"]["false_positive_rate"] <= 0.06 and challenge["phishing_band"]["false_positive_rate"] <= 0.06
    assert logo["at_least_suspicious"]["recall"] >= 0.70
    # a recall of exactly 100 % on held-out families with zero false positives would point to leakage, not skill
    assert not (logo["phishing_band"]["recall"] == 1.0 and logo["phishing_band"]["false_positive_rate"] == 0.0)
    old = report["baseline_template_model"]["challenge_set"]
    assert challenge["phishing_band"]["false_positive_rate"] < old["phishing_band"]["false_positive_rate"]


def test_retraining_reproduces_the_shipped_model(tmp_path):
    pytest.importorskip("sklearn")
    from ml_models import train_model
    assert train_model.main(["--out", str(tmp_path), "--no-eval"]) == 0
    shipped = json.loads((MODEL_DIR / MODEL_JSON_NAME).read_text(encoding="utf-8"))
    fresh = json.loads((tmp_path / MODEL_JSON_NAME).read_text(encoding="utf-8"))
    assert set(fresh["terms"]) == set(shipped["terms"])
    assert fresh["stack"]["features"] == shipped["stack"]["features"]
    assert fresh["stack"]["weights"] == pytest.approx(shipped["stack"]["weights"], abs=1e-6)
    assert fresh["stack"]["bias"] == pytest.approx(shipped["stack"]["bias"], abs=1e-6)
    assert fresh["stack"]["nb_weight"] == pytest.approx(shipped["stack"]["nb_weight"], abs=1e-6)
