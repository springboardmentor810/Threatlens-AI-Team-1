"""Comprehensive end-to-end verification script for ThreatLens-Integration."""
import sys
import json
import csv
import io
from pathlib import Path

sys.path.insert(0, "backend")
sys.path.insert(0, ".")

from fastapi.testclient import TestClient
from app.main import app

EICAR_BYTES = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}"
    + b"$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"
    + b"$H+H*"
)

def run_tests():
    print("=" * 60)
    print("THREATLENS-INTEGRATION END-TO-END VALIDATION")
    print("=" * 60)

    with TestClient(app) as client:
        # 1. PE Test (AI / EMBER Inference)
        print("\n--- 1. Testing Safe Benign PE File Upload (AI Inference) ---")
        sample_pe_path = Path("tests/fixtures/sample_benign.exe")
        if not sample_pe_path.is_file():
            import shutil
            notepad = Path(r"C:\Windows\System32\notepad.exe")
            if notepad.is_file():
                sample_pe_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(notepad, sample_pe_path)

        pe_bytes = sample_pe_path.read_bytes()
        res_pe = client.post(
            "/api/v1/upload",
            files={"file": ("sample_benign.exe", io.BytesIO(pe_bytes), "application/octet-stream")},
        )
        assert res_pe.status_code == 200, f"PE upload failed: {res_pe.text}"
        pe_json = res_pe.json()
        ai = pe_json.get("ai_analysis", {})
        print(f"Status Code: {res_pe.status_code}")
        print(f"AI Status: {ai.get('status')}")
        print(f"AI Available: {ai.get('available')}")
        print(f"AI Model: {ai.get('model')}")
        print(f"AI Verdict: {ai.get('verdict')}")
        print(f"Malware Probability: {ai.get('malware_probability')}")
        print(f"Confidence: {ai.get('confidence_percentage')}%")
        print(f"Risk Score: {ai.get('risk_score')}")
        pe_threat_id = pe_json.get("detection", {}).get("threat_id") or pe_json.get("detection", {}).get("id")
        print(f"Recorded Threat ID: {pe_threat_id}")

        assert ai.get("available") is True
        assert ai.get("status") == "Executed"
        assert ai.get("verdict") in {"BENIGN", "MALWARE"}

        # 2. EICAR Antivirus Test File Upload (Static / YARA)
        print("\n--- 2. Testing EICAR Test File Upload (YARA Static Detection) ---")
        res_eicar = client.post(
            "/api/v1/upload",
            files={"file": ("eicar_test.pdf", io.BytesIO(EICAR_BYTES), "application/octet-stream")},
        )
        assert res_eicar.status_code == 200, f"EICAR upload failed: {res_eicar.text}"
        eicar_json = res_eicar.json()
        yara_matches = eicar_json.get("yara_results", {}).get("matched_rules", [])
        detection = eicar_json.get("detection", {})
        print(f"Status Code: {res_eicar.status_code}")
        print(f"YARA Matches: {yara_matches}")
        print(f"Detection Prediction: {detection.get('prediction')}")
        print(f"Detection Confidence: {detection.get('confidence')}%")
        print(f"Detection Risk Score: {detection.get('risk_score')}")
        eicar_threat_id = detection.get("threat_id") or detection.get("id")
        print(f"EICAR Threat ID: {eicar_threat_id}")

        assert "EICAR_Test_File" in yara_matches
        assert detection.get("prediction") == "Malware"
        assert detection.get("confidence") >= 90.0

        # 3. Non-PE Clean Document Upload (PDF)
        print("\n--- 3. Testing Clean Document Upload (Non-PE) ---")
        clean_pdf_bytes = b"%PDF-1.4 1 0 obj << /Type /Catalog >> endobj xref 0 1 0000000000 65535 f trailer << /Root 1 0 R >> startxref 40 %%EOF"
        res_clean = client.post(
            "/api/v1/upload",
            files={"file": ("clean_report.pdf", io.BytesIO(clean_pdf_bytes), "application/pdf")},
        )
        assert res_clean.status_code == 200
        clean_json = res_clean.json()
        clean_ai = clean_json.get("ai_analysis", {})
        print(f"Status Code: {res_clean.status_code}")
        print(f"AI Status: {clean_ai.get('status')}")
        print(f"AI Available: {clean_ai.get('available')}")
        print(f"AI Reason: {clean_ai.get('reason')}")
        print(f"Prediction: {clean_json.get('detection', {}).get('prediction')}")

        assert clean_ai.get("available") is False
        assert clean_ai.get("status") == "Not Applicable"

        # 4. Individual Threat PDF Download
        print("\n--- 4. Testing Individual Threat Report PDF Download ---")
        res_pdf = client.get(f"/api/v1/threats/{eicar_threat_id}/report/pdf")
        print(f"Status Code: {res_pdf.status_code}")
        print(f"Content-Type: {res_pdf.headers.get('content-type')}")
        print(f"Content-Disposition: {res_pdf.headers.get('content-disposition')}")
        print(f"PDF Header: {res_pdf.content[:5]} (Size: {len(res_pdf.content)} bytes)")

        assert res_pdf.status_code == 200
        assert res_pdf.headers.get("content-type") == "application/pdf"
        assert res_pdf.content.startswith(b"%PDF-")

        # 5. Summary PDF Download
        print("\n--- 5. Testing Executive Summary PDF Download ---")
        res_sum_pdf = client.get("/api/v1/threats/reports/summary/pdf?days=30")
        print(f"Status Code: {res_sum_pdf.status_code}")
        print(f"Content-Type: {res_sum_pdf.headers.get('content-type')}")
        print(f"Content-Disposition: {res_sum_pdf.headers.get('content-disposition')}")
        print(f"PDF Header: {res_sum_pdf.content[:5]} (Size: {len(res_sum_pdf.content)} bytes)")

        assert res_sum_pdf.status_code == 200
        assert res_sum_pdf.headers.get("content-type") == "application/pdf"
        assert res_sum_pdf.content.startswith(b"%PDF-")

        # 6. CSV Export
        print("\n--- 6. Testing CSV Export ---")
        res_csv = client.get("/api/v1/threats/export/csv")
        print(f"Status Code: {res_csv.status_code}")
        print(f"Content-Type: {res_csv.headers.get('content-type')}")
        print(f"Content-Disposition: {res_csv.headers.get('content-disposition')}")
        
        reader = list(csv.reader(io.StringIO(res_csv.text)))
        print(f"CSV Headers: {reader[0]}")
        print(f"Total rows exported: {len(reader) - 1}")
        for i, row in enumerate(reader[1:], 1):
            print(f"  Row {i}: Filename={row[1]}, Score={row[6]}, Prediction={row[7]}, Confidence={row[8]}, YARA={row[11]}, Engine={row[10]}")

        assert res_csv.status_code == 200
        assert "text/csv" in res_csv.headers.get("content-type")
        assert len(reader) >= 4  # Header + 3 uploads

        print("\n" + "=" * 60)
        print("ALL END-TO-END VERIFICATION CHECKS PASSED SUCCESSFULLY!")
        print("=" * 60)

if __name__ == "__main__":
    run_tests()
