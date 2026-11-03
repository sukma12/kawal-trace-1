from pathlib import Path


def test_integration_wizard_has_simple_modes_and_separate_health_indicators():
    source = Path(__file__).resolve().parents[1].joinpath("main.py").read_text(encoding="utf-8")
    for phrase in (
        "WIZARD INTEGRASI · PILIH JENIS SERVER",
        "Server sudah punya API log (paling mudah)",
        "API Kawal Trace (enrollment + feed)",
        "Log hanya ada di server (perlu agen/collector)",
        "Cari endpoint REST",
        "API TERJANGKAU",
        "FEED BERHASIL",
        "AGEN BELUM DIVERIFIKASI",
        "DETEKSI DIJALANKAN",
        "NOTIFIKASI SISTEM AKTIF",
    ):
        assert phrase in source


def test_advanced_api_mapping_is_collapsed_by_default():
    source = Path(__file__).resolve().parents[1].joinpath("main.py").read_text(encoding="utf-8")
    assert 'advanced_api_settings_panel = ft.Container(\n        visible=False' in source
    assert "Pengaturan lanjutan · mapping / pagination" in source


def test_public_user_flow_does_not_claim_any_url_exposes_private_logs():
    source = Path(__file__).resolve().parents[1].joinpath("main.py").read_text(encoding="utf-8")
    assert "Koneksi ke website saja tidak berarti log host tersedia." in source
    assert "jangan pasang agen ke server pihak lain tanpa persetujuan." in source
