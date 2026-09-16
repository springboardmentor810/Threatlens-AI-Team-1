"""
The graded static-analysis verdict, exercised with the sample documents in
samples/.

Those files are harmless PDFs whose text contains the strings the YARA rules
look for - the EICAR idea applied to this pipeline. Each is written to land in
a specific risk band, so this suite doubles as a regression check on the
scoring: a rule change or a threshold change that moves one of them out of its
band fails here rather than being noticed in a demo.
"""

from pathlib import Path

import pytest

from app.api.upload import derive_static_verdict, detect_urls_ips, run_yara
from app.modules.threat_monitoring.risk_score import calculate_risk_score

SAMPLES = Path(__file__).resolve().parents[2] / "samples"

pytestmark = pytest.mark.skipif(
    not SAMPLES.is_dir(), reason="samples/ directory not present"
)


def _score(name: str):
    path = SAMPLES / name
    assert path.is_file(), f"missing sample {name}"
    yara = run_yara(str(path))
    assert "error" not in yara, yara
    prediction, confidence, engine = derive_static_verdict(yara)
    indicators = {k: v for k, v in detect_urls_ips(str(path)).items() if v}
    score, level = calculate_risk_score(
        confidence, prediction, yara.get("matched_rules"), indicators or None
    )
    return {
        "rules": set(yara["matched_rules"]),
        "prediction": prediction,
        "confidence": confidence,
        "engine": engine,
        "score": score,
        "level": level,
    }


# =====================================================================
# One band per sample
# =====================================================================

@pytest.mark.parametrize(
    "name, prediction, rules",
    [
        ("low-1-suspicious-api.pdf", "Suspicious", {"Suspicious_APIs"}),
        ("low-2-powershell.pdf", "Downloader", {"Embedded_PowerShell"}),
        ("low-3-pdf-javascript.pdf", "Exploit", {"PDF_JavaScript"}),
        ("low-4-autolaunch.pdf", "Dropper", {"PDF_AutoLaunch"}),
    ],
)
def test_single_weak_indicator_is_low_risk(name, prediction, rules):
    r = _score(name)
    assert r["rules"] == rules
    assert r["prediction"] == prediction
    assert r["level"] == "low", r
    assert 30 <= r["score"] < 50


@pytest.mark.parametrize(
    "name, prediction",
    [
        ("high-1-ransom-note.pdf", "Ransomware"),
        ("high-2-rat-loader.pdf", "RAT"),
    ],
)
def test_two_rules_with_a_serious_family_is_high_risk(name, prediction):
    r = _score(name)
    assert len(r["rules"]) == 2
    assert r["prediction"] == prediction
    assert r["level"] == "high", r
    assert 70 <= r["score"] < 85


def test_three_rules_ransomware_and_indicators_is_critical():
    r = _score("critical-1-ransomware-dropper.pdf")
    assert len(r["rules"]) == 3
    assert r["prediction"] == "Ransomware"
    assert r["level"] == "critical", r
    assert r["score"] >= 85


# =====================================================================
# The grading rules themselves
# =====================================================================

def test_the_worst_family_names_the_verdict():
    """A file matching both a suspicious-API and a ransomware rule is ransomware."""
    r = _score("high-1-ransom-note.pdf")
    assert r["rules"] == {"Suspicious_APIs", "Ransomware_Note"}
    assert r["prediction"] == "Ransomware"


def test_confidence_rises_with_independent_evidence():
    one = _score("low-1-suspicious-api.pdf")["confidence"]
    two = _score("high-1-ransom-note.pdf")["confidence"]
    three = _score("critical-1-ransomware-dropper.pdf")["confidence"]
    assert one < two < three


def test_static_confidence_never_reaches_the_ai_ensemble_ceiling():
    """Only EICAR, a definitive signature, is reported at 99."""
    for name in (
        "low-1-suspicious-api.pdf",
        "high-2-rat-loader.pdf",
        "critical-1-ransomware-dropper.pdf",
    ):
        assert _score(name)["confidence"] <= 95


def test_acronym_families_keep_their_case():
    assert _score("high-2-rat-loader.pdf")["prediction"] == "RAT"


def test_verdict_records_that_it_came_from_static_analysis():
    for name in ("low-3-pdf-javascript.pdf", "critical-1-ransomware-dropper.pdf"):
        assert "Static analysis" in _score(name)["engine"]


def test_empty_indicator_categories_do_not_add_risk():
    """
    The scorer adds +2 per indicator category present. detect_urls_ips always
    returns both keys, so passing the dict unfiltered used to add +4 to every
    file, including ones with no URLs or IPs at all.
    """
    yara = run_yara(str(SAMPLES / "low-1-suspicious-api.pdf"))
    prediction, confidence, _ = derive_static_verdict(yara)
    raw = detect_urls_ips(str(SAMPLES / "low-1-suspicious-api.pdf"))
    assert raw == {"urls": [], "ip_addresses": []}

    inflated, _ = calculate_risk_score(confidence, prediction, yara["matched_rules"], raw)
    honest, _ = calculate_risk_score(confidence, prediction, yara["matched_rules"], None)
    assert inflated == honest + 4, "the unfiltered dict is still counted as two categories"


def test_rules_without_metadata_still_classify():
    """Third-party rule files will not carry family/severity; degrade sanely."""
    prediction, confidence, _ = derive_static_verdict(
        {"matched_rules": ["Some_Vendor_Rule"]}  # no "matches" key at all
    )
    assert prediction == "Suspicious"
    assert confidence == 55.0
