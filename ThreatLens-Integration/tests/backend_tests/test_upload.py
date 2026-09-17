"""
Tests for the File Upload & Static Analysis module (Member 2).

Replaces the branch's `test_ember.py`, which was a scratch script rather than a
test: it ran at import time against a hardcoded path on one developer's machine
(C:\\Users\\GAYATHRI\\Downloads\\normal.exe), so collecting it would have failed
the suite on every other machine.

Uploads are redirected to a tmp_path so the tests never write into
backend/storage/uploaded_files.
"""

import hashlib
import io

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.api import upload as upload_module

client = TestClient(app)


@pytest.fixture(autouse=True)
def _isolate_upload_dir(tmp_path, monkeypatch):
    """Write uploads to a temp dir and start each test with an empty report store."""
    monkeypatch.setattr(upload_module, "UPLOAD_FOLDER", str(tmp_path))
    monkeypatch.setattr(upload_module, "REPORTS", {})
    yield


def _post(content: bytes, filename: str = "sample.exe"):
    return client.post(
        "/api/v1/upload",
        files={"file": (filename, io.BytesIO(content), "application/octet-stream")},
    )


# =====================================================================
# VALIDATION
# =====================================================================

@pytest.mark.parametrize("filename", ["a.exe", "a.dll", "a.pdf", "a.doc", "a.docx", "a.zip"])
def test_allowed_extensions_are_accepted(filename):
    assert _post(b"harmless content", filename).status_code == 200


@pytest.mark.parametrize("filename", ["a.txt", "a.sh", "a.py", "noextension"])
def test_unsupported_extensions_are_rejected(filename):
    resp = _post(b"harmless content", filename)
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Unsupported file type"


def test_extension_check_is_case_insensitive():
    assert _post(b"content", "SAMPLE.EXE").status_code == 200


# =====================================================================
# RESPONSE CONTRACT
# =====================================================================

def test_response_keeps_the_original_upload_fields():
    """
    The pre-merge endpoint returned exactly these three keys. Member 2's
    version adds analysis on top; it must not drop them, because the frontend's
    uploadApi is written against them.
    """
    body = _post(b"content", "keep.exe").json()
    assert body["message"] == "File uploaded successfully"
    assert body["original_filename"] == "keep.exe"
    assert body["stored_filename"].endswith(".exe")


def test_stored_filename_is_randomised_per_upload():
    first = _post(b"same bytes", "dup.exe").json()["stored_filename"]
    second = _post(b"same bytes", "dup.exe").json()["stored_filename"]
    assert first != second


def test_hashes_match_the_uploaded_bytes():
    content = b"deadbeef" * 32
    body = _post(content, "hash.exe").json()
    assert body["hashes"]["md5"] == hashlib.md5(content).hexdigest()
    assert body["hashes"]["sha256"] == hashlib.sha256(content).hexdigest()


def test_metadata_reports_size_and_extension():
    content = b"x" * 1234
    meta = _post(content, "meta.exe").json()["metadata"]
    assert meta["size_bytes"] == 1234
    assert meta["extension"] == ".exe"
    assert meta["filename"] == "meta.exe"


# =====================================================================
# ANALYSIS
# =====================================================================

def test_urls_and_ips_are_extracted():
    content = b"connect to https://evil.example.com/payload then 192.168.1.77 done"
    urls_ips = _post(content, "c2.exe").json()["urls_ips"]
    assert "https://evil.example.com/payload" in urls_ips["urls"]
    assert "192.168.1.77" in urls_ips["ip_addresses"]


def test_yara_rule_matches_suspicious_api_strings():
    """Exercises backend/app/yara_rules/malware_rules.yar (Suspicious_APIs)."""
    pytest.importorskip("yara")
    content = b"padding VirtualAlloc padding CreateRemoteThread padding"
    result = _post(content, "susp.exe").json()["yara_results"]
    assert "error" not in result, result
    assert "Suspicious_APIs" in result["matched_rules"]


def test_yara_reports_no_match_for_clean_content():
    pytest.importorskip("yara")
    result = _post(b"nothing interesting here at all", "clean.exe").json()["yara_results"]
    assert result.get("matched_rules") == []


def test_non_pe_file_is_reported_as_such():
    body = _post(b"this is definitely not a PE binary", "fake.exe").json()
    assert "error" in body["pe_header"]


def test_imports_found_is_zero_for_a_non_pe_file():
    """
    analyze_imports returns {"error": ...} for anything unparseable; the report
    counted that dict and reported imports_found == 1 where there were none.
    """
    body = _post(b"not a PE", "fake.exe").json()
    report_url = body["report_url"]
    report = client.get(report_url).json()
    assert report["analysis"]["pe_file"] == "No"
    assert report["analysis"]["imports_found"] == 0


# =====================================================================
# REPORT RETRIEVAL
# =====================================================================

def test_report_is_retrievable_after_upload():
    body = _post(b"VirtualAlloc here", "rep.exe").json()
    resp = client.get(body["report_url"])
    assert resp.status_code == 200
    report = resp.json()
    assert report["summary"]["filename"] == "rep.exe"
    assert report["summary"]["md5"] == body["hashes"]["md5"]


def test_unknown_report_returns_404():
    resp = client.get("/api/v1/report/does-not-exist.exe")
    assert resp.status_code == 404


# =====================================================================
# GRACEFUL DEGRADATION
#
# Each native backend is optional. A missing one must degrade that single
# analysis, not take down the API — app.main imports this router, so an
# ImportError here would break auth, alerts and threat monitoring too.
# =====================================================================

def test_upload_still_works_without_python_magic(monkeypatch):
    monkeypatch.setattr(upload_module, "magic", None)
    body = _post(b"content", "nomagic.exe").json()
    assert "error" in body["file_type"]
    report = client.get(body["report_url"]).json()
    assert report["summary"]["file_type"] == "unknown"


def test_upload_still_works_without_pefile(monkeypatch):
    monkeypatch.setattr(upload_module, "pefile", None)
    body = _post(b"content", "nopefile.exe").json()
    assert body["pe_header"]["error"] == "pefile is not installed"
    assert body["imports"]["error"] == "pefile is not installed"


def test_upload_still_works_without_yara(monkeypatch):
    monkeypatch.setattr(upload_module, "yara", None)
    body = _post(b"content", "noyara.exe").json()
    assert body["yara_results"]["error"] == "yara-python is not installed"


def test_missing_yara_rule_file_is_reported_not_raised(monkeypatch):
    monkeypatch.setattr(upload_module, "YARA_RULES", "/nonexistent/rules.yar")
    body = _post(b"content", "norules.exe").json()
    assert "not found" in body["yara_results"]["error"]


# =====================================================================
# EMBER FEATURE EXTRACTION
#
# EMBER is not on PyPI, so these skip unless it has been installed from git.
# The contract they pin is the one ml_model/inference/ai_predictor.py enforces.
# =====================================================================

def test_ember_feature_contract_matches_the_model_input_width():
    from app.services import ember_extractor

    assert ember_extractor.EXPECTED_FEATURE_COUNT == 2381
    assert len(ember_extractor.FEATURE_COLUMNS) == 2381
    assert ember_extractor.FEATURE_COLUMNS[0] == "F1"
    assert ember_extractor.FEATURE_COLUMNS[-1] == "F2381"


def test_ember_module_imports_without_ember_installed():
    """Importing must not raise even when EMBER is absent."""
    from app.services import ember_extractor

    assert callable(ember_extractor.extract_ember_features)
    assert isinstance(ember_extractor.is_available(), bool)


def test_ember_extraction_reports_a_clear_error_when_unavailable(tmp_path):
    from app.services import ember_extractor

    if ember_extractor.is_available():
        pytest.skip("EMBER is installed; the unavailable path cannot be exercised")

    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"not a real PE")
    with pytest.raises(RuntimeError, match="EMBER is not installed"):
        ember_extractor.extract_ember_features(str(sample))


def test_ember_missing_file_raises_before_touching_ember(tmp_path):
    from app.services import ember_extractor

    with pytest.raises(FileNotFoundError):
        ember_extractor.extract_ember_features(str(tmp_path / "absent.exe"))
