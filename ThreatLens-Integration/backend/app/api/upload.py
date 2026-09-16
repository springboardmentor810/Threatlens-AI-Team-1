import logging
import os
import uuid
import shutil
import hashlib
import mimetypes
import re
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, UploadFile, File, HTTPException
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.database.database import get_db

logger = logging.getLogger("threatlens.upload")

# ---------------------------------------------------------------------------
# Optional native analysis backends
#
# python-magic, pefile and yara-python each wrap a native library. Importing
# them at module scope means one missing system package takes the *entire* API
# down, auth and alerts included, because app.main imports this router. Each is
# therefore optional: when a backend is unavailable its analyser returns the
# same {"error": ...} shape the module already uses for unanalysable files, so
# an upload still succeeds with the remaining analyses.
#
# Install them all with: pip install -r backend/requirements.txt
# ---------------------------------------------------------------------------

try:
    import magic
except ImportError:  # pragma: no cover - depends on the host
    magic = None
    logger.warning("python-magic unavailable; MIME type detection disabled.")

try:
    import pefile
except ImportError:  # pragma: no cover
    pefile = None
    logger.warning("pefile unavailable; PE header and import analysis disabled.")

try:
    import yara
except ImportError:  # pragma: no cover
    yara = None
    logger.warning("yara-python unavailable; YARA rule matching disabled.")


# Prefixed so every route shares one base path; this endpoint was "/upload".
router = APIRouter(prefix="/api/v1", tags=["File Analysis"])

# Resolve paths against this package rather than the current working
# directory, so behaviour does not depend on where uvicorn/pytest was started.
# backend/app/api/upload.py -> parents[1] is backend/app, parents[2] is backend.
_APP_DIR = Path(__file__).resolve().parents[1]
_BACKEND_DIR = Path(__file__).resolve().parents[2]

UPLOAD_FOLDER = str(_BACKEND_DIR / "storage" / "uploaded_files")
YARA_RULES = str(_APP_DIR / "yara_rules" / "malware_rules.yar")
REPORTS = {}
# Create folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {
    ".exe",
    ".dll",
    ".pdf",
    ".doc",
    ".docx",
    ".zip"
}
def calculate_hashes(file_path):
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while chunk := file.read(4096):
            md5.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha256": sha256.hexdigest()
    }
def extract_metadata(file_path, original_filename, size_bytes=None):
    try:
        file_stats = os.stat(file_path)
        size = file_stats.st_size
        c_time = datetime.fromtimestamp(file_stats.st_ctime).isoformat()
        m_time = datetime.fromtimestamp(file_stats.st_mtime).isoformat()
    except Exception:
        size = size_bytes or 0
        now_iso = datetime.now().isoformat()
        c_time, m_time = now_iso, now_iso

    return {
        "filename": original_filename,
        "extension": os.path.splitext(original_filename)[1].lower(),
        "size_bytes": size,
        "mime_type": mimetypes.guess_type(original_filename)[0],
        "created_at": c_time,
        "modified_at": m_time,
    }
def detect_file_type(file_path):
    if magic is None:
        return {
            "error": "python-magic is not installed"
        }

    try:
        mime_type = magic.from_file(file_path, mime=True)
        description = magic.from_file(file_path)
        return {
            "mime_type": mime_type,
            "description": description
        }
    except Exception as e:
        return {
            "error": f"Failed to detect file type: {e}"
        }
def analyze_pe_header(file_path):
    if pefile is None:
        return {
            "error": "pefile is not installed"
        }

    try:
        pe = pefile.PE(file_path)

        return {
            "machine": hex(pe.FILE_HEADER.Machine),
            "number_of_sections": pe.FILE_HEADER.NumberOfSections,
            "timestamp": pe.FILE_HEADER.TimeDateStamp,
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
            "subsystem": pe.OPTIONAL_HEADER.Subsystem,
            "characteristics": hex(pe.FILE_HEADER.Characteristics)
        }

    except Exception:
        return {
            "error": "Not a valid PE file"
        }
def analyze_imports(file_path):
    if pefile is None:
        return {
            "error": "pefile is not installed"
        }

    try:
        pe = pefile.PE(file_path)

        imports = {}

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode(
                    "utf-8", errors="ignore"
                )

                api_names = []

                for imp in entry.imports:
                    if imp.name:
                        api_names.append(
                            imp.name.decode(
                                "utf-8", errors="ignore"
                            )
                        )
                    else:
                        api_names.append(
                            f"Ordinal_{imp.ordinal}"
                        )

                imports[dll_name] = api_names

        return imports

    except Exception:
        return {
            "error": "Not a valid PE file"
        }
def detect_urls_ips(file_path, content=None):
    if content is None:
        try:
            with open(file_path, "rb") as file:
                content = file.read()
        except Exception:
            content = b""

    text = content.decode("latin-1", errors="ignore")

    url_pattern = r"https?://[^\s\"'<>]+"
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    urls = sorted(set(re.findall(url_pattern, text)))
    ips = sorted(set(re.findall(ip_pattern, text)))

    return {
        "urls": urls,
        "ip_addresses": ips
    }
def run_yara(file_path, content=None):
    if yara is None:
        return {
            "error": "yara-python is not installed"
        }

    if not os.path.exists(YARA_RULES):
        return {
            "error": f"YARA rule file not found: {YARA_RULES}"
        }

    try:
        rules = yara.compile(filepath=YARA_RULES)
        if content is not None:
            matches = rules.match(data=content)
        else:
            matches = rules.match(file_path)

        return {
            "matched_rules": [match.rule for match in matches],
            # Per-rule metadata the static verdict reads. Rules without it
            # (third-party rule files) fall back to a generic low-severity hit.
            "matches": [
                {
                    "rule": match.rule,
                    "family": str(match.meta.get("family", "suspicious")),
                    "severity": str(match.meta.get("severity", "low")),
                    "description": str(match.meta.get("description", "")),
                }
                for match in matches
            ],
        }

    except Exception as e:
        return {
            "error": str(e)
        }
def generate_analysis_report(
    metadata,
    file_type,
    pe_header,
    imports,
    urls_ips,
    yara_results,
    hashes
):
    report = {
        "summary": {
            "filename": metadata["filename"],
            # detect_file_type returns {"error": ...} when python-magic is
            # missing, so there is no "description" key to read in that case.
            "file_type": file_type.get("description", "unknown"),
            "file_size": metadata["size_bytes"],
            "md5": hashes["md5"],
            "sha256": hashes["sha256"]
        },

        "analysis": {
            "pe_file":
                "Yes" if "error" not in pe_header else "No",

            # analyze_imports returns {"error": ...} for anything that is not a
            # parseable PE; counting that dict reported one import where there
            # were none.
            "imports_found":
                len(imports) if isinstance(imports, dict) and "error" not in imports else 0,

            "urls_found":
                len(urls_ips["urls"]),

            "ip_addresses_found":
                len(urls_ips["ip_addresses"]),

            "yara_matches":
                yara_results.get("matched_rules", [])
        }
    }

    return report
async def run_ai_analysis(file_path, pe_header):
    """
    Featurise the upload with EMBER and score it with the AI ensemble.

    Returns a dict with `available` and `status`.
    """
    from app.ml import predictor
    from app.services import ember_extractor

    # EMBER v2 features describe a PE. analyze_pe_header() has already told us
    # whether this file parses as one.
    if "error" in pe_header:
        logger.info("[AI] File type detected: Non-PE (%s)", pe_header.get("error", "Not a PE"))
        return {
            "available": False,
            "status": "Not Applicable",
            "reason": "EMBER analysis is available only for supported PE binaries.",
        }

    logger.info("[AI] File type detected: PE")

    if not ember_extractor.is_available():
        logger.warning("[AI] EMBER extractor is not installed.")
        return {
            "available": False,
            "status": "Analysis unavailable",
            "reason": (
                "EMBER is not installed. Install it with "
                "'pip install git+https://github.com/elastic/ember.git'."
            ),
        }

    if not predictor.is_available():
        logger.warning("[AI] AI models unavailable in %s", predictor.model_dir())
        return {
            "available": False,
            "status": "Analysis unavailable",
            "reason": f"AI models unavailable (looked in {predictor.model_dir()}).",
        }

    try:
        logger.info("[AI] Extracting EMBER features...")
        features = await run_in_threadpool(
            ember_extractor.extract_ember_features, file_path
        )
        dimension = features.shape[1] if hasattr(features, "shape") else len(features)
        logger.info("[AI] Feature extraction successful: %s", dimension)
    except Exception as exc:
        logger.exception("[AI] EMBER feature extraction failed for %s", file_path)
        return {
            "available": False,
            "status": "Analysis unavailable",
            "reason": f"Feature extraction failed: {exc}",
        }

    try:
        logger.info("[AI] Loading model...")
        pred_instance = predictor.get_predictor()
        if pred_instance is not None:
            logger.info("[AI] Model loaded successfully")
        logger.info("[AI] Running inference...")
        result = await predictor.predict(features)
    except Exception as exc:
        logger.exception("[AI] AI prediction failed for %s", file_path)
        return {
            "available": False,
            "status": "Analysis unavailable",
            "reason": f"Prediction failed: {exc}",
        }

    if result is None:
        logger.warning("[AI] AI models unavailable during inference.")
        return {
            "available": False,
            "status": "Analysis unavailable",
            "reason": "AI models unavailable.",
        }

    malware_prob = result.get("malware_probability", 0.0)
    verdict = result.get("verdict", "BENIGN")
    risk_score = result.get("risk_score", 0)

    logger.info("[AI] Prediction: %s", verdict)
    logger.info("[AI] Malware probability: %s", malware_prob)
    logger.info("[AI] Risk score: %s (%s)", risk_score, result.get("risk_level"))
    logger.debug("[AI] Per-model probabilities: %s", result.get("model_probabilities"))

    # The AI module is consumed as a prediction service: the response carries
    # the verdict and its scores, not how they were produced. Per-model
    # probabilities, ensemble weights and the feature vector stay server-side -
    # they are implementation detail, and exposing them invites the UI to
    # depend on the ensemble's shape.
    #
    # Note this deliberately does NOT return a "confidence": the previous
    # confidence_percentage was class confidence, inverted for benign files, so
    # a benign verdict at 0.06 malware probability reported 94%. Labelling that
    # "malware probability" in the UI would have been badly wrong. Callers get
    # malware_probability and nothing that can be mistaken for it.
    return {
        "available": True,
        "status": "Executed",
        "verdict": verdict,
        "malware_probability": malware_prob,
        "risk_score": risk_score,
        "risk_level": result.get("risk_level"),
        "model": result.get("model"),
    }


# How much a single rule hit is worth on its own, by the severity declared in
# its metadata. Each further independent rule adds _CONFIDENCE_PER_EXTRA_RULE.
_SEVERITY_CONFIDENCE = {"low": 55, "medium": 65, "high": 75, "critical": 99}
_CONFIDENCE_PER_EXTRA_RULE = 15
_CONFIDENCE_CAP = 95

# Families ranked so the worst one matched names the verdict. Mirrors the
# ordering of the risk scorer's family bonus table.
# Display form of a family name; acronyms stay upper-case.
_FAMILY_LABEL = {"suspicious": "Suspicious", "rat": "RAT", "pup": "PUP"}

_FAMILY_RANK = [
    "eicar", "ransomware", "rootkit", "backdoor", "rat", "trojan", "worm",
    "spyware", "keylogger", "botnet", "exploit", "dropper", "downloader",
    "adware", "pup", "suspicious",
]


def derive_static_verdict(yara_results):
    """
    Classify a file the AI ensemble cannot score, using static analysis alone.

    Returns (prediction, confidence, detection_engine).

    The verdict is graded rather than binary:

      * the prediction is the most serious family among the matched rules
        ("Ransomware" outranks "Suspicious"), which is what the risk scorer's
        family bonus keys on;
      * confidence starts from the strongest single rule's declared severity
        and rises with every additional independent rule that fired, capped
        below the certainty reserved for the AI ensemble - except EICAR, which
        is a definitive test signature and is reported as confirmed malware.

    No hit, with the rules having actually run, is a real negative result and
    is recorded as benign. Only when the rules could not run at all is the
    file genuinely unscanned.
    """
    from app.modules.threat_monitoring.service import UNSCANNED_PREDICTION

    engine = "Static analysis (YARA + indicators)"

    if "error" in yara_results:
        return UNSCANNED_PREDICTION, 0.0, "Unavailable"

    matches = yara_results.get("matches") or [
        {"rule": r, "family": "suspicious", "severity": "low"}
        for r in (yara_results.get("matched_rules") or [])
    ]

    if not matches:
        return "Benign", 0.0, engine

    families = {m.get("family", "suspicious").lower() for m in matches}
    if "eicar" in families:
        return "Malware", 99.0, engine

    worst = next((f for f in _FAMILY_RANK if f in families), "suspicious")
    prediction = _FAMILY_LABEL.get(worst, worst.capitalize())

    strongest = max(
        _SEVERITY_CONFIDENCE.get(m.get("severity", "low").lower(), 55) for m in matches
    )
    confidence = min(
        strongest + _CONFIDENCE_PER_EXTRA_RULE * (len(matches) - 1),
        _CONFIDENCE_CAP,
    )

    return prediction, float(confidence), engine


def record_detection(db, *, metadata, hashes, ai_analysis, yara_results,
                     urls_ips, analysis_report):
    """
    Persist the scan through the Threat Monitoring service.

    Deliberately reuses ThreatMonitoringService.record_detection rather than
    writing to ThreatLog here: that one call already does risk scoring, the
    PostgreSQL row, MongoDB audit logging, the timeline event and the alert
    trigger. Duplicating any of it would mean two code paths to keep in step.

    Every scan is recorded and every scan reaches a verdict.

    The AI ensemble only applies to PE binaries - EMBER v2 features describe a
    Portable Executable, so a PDF or an archive cannot be scored by it. That is
    a limit of the model, not a failure to analyse: static analysis still ran
    and produced real evidence. Those files are therefore classified from that
    evidence rather than parked as unscored, which is what left a clean PDF
    reading "Unscanned" in the history.

    "Unscanned" survives for the case it was meant for: analysis that could not
    run at all, when even YARA is unavailable. It alerts on nothing and counts
    as neither malware nor benign.
    """
    from app.modules.threat_monitoring.schemas import ThreatLogCreate
    from app.modules.threat_monitoring.service import (
        UNSCANNED_PREDICTION,
        ThreatMonitoringService,
    )

    scored = bool(ai_analysis.get("available"))

    if scored:
        # "Malware"/"Benign" are what the monitoring service and the alert
        # adapter test against; both lower-case the value and compare to a
        # benign set, so "Benign" suppresses the alert and "Malware" raises one.
        prediction = "Malware" if ai_analysis["verdict"] == "MALWARE" else "Benign"
        confidence = round(ai_analysis["malware_probability"] * 100, 2)
        engine = ai_analysis.get("model", "ThreatLens AI")
    else:
        prediction, confidence, engine = derive_static_verdict(yara_results)

    # Say plainly how the verdict was reached, so a file classified without the
    # AI is not mistaken for one the ensemble scored.
    description = None
    if not scored:
        reason = ai_analysis.get("reason", "the AI model did not run")
        description = (
            f"File '{metadata['filename']}' classified by static analysis as "
            f"{prediction.lower()}. The AI ensemble was not applied: {reason}"
        )

    payload = ThreatLogCreate(
        description=description,
        filename=metadata["filename"],
        file_hash_md5=hashes["md5"],
        file_hash_sha256=hashes["sha256"],
        file_size=metadata["size_bytes"],
        file_type=(metadata["extension"] or "").lstrip("."),
        prediction=prediction,
        # ThreatLogCreate wants a 0-100 percentage; the model reports 0-1.
        confidence=confidence,
        detection_engine=engine,
        yara_matches=yara_results.get("matched_rules") or None,
        static_analysis_results=analysis_report,
        # The risk scorer adds +2 per indicator *category present*. Passing the
        # raw dict counted its two always-present keys even when both lists
        # were empty, inflating every score by 4 for nothing.
        suspicious_indicators={k: v for k, v in (urls_ips or {}).items() if v} or None,
    )

    return ThreatMonitoringService.record_detection(db, payload)


@router.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):

    # Get file extension
    extension = os.path.splitext(file.filename)[1].lower()

    # Validate extension
    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail="Unsupported file type"
        )

    # Generate unique filename
    unique_filename = f"{uuid.uuid4()}{extension}"

    # Full path
    file_path = os.path.join(
        UPLOAD_FOLDER,
        unique_filename
    )

    # Ensure upload directory exists
    os.makedirs(os.path.dirname(file_path), exist_ok=True)

    # Read uploaded file content
    content = await file.read()
    size_bytes = len(content)

    # Save uploaded file to disk
    try:
        with open(file_path, "wb") as buffer:
            buffer.write(content)
    except Exception as exc:
        logger.warning("Could not write upload to %s: %s", file_path, exc)

    # Calculate cryptographic hashes in-memory
    md5_str = hashlib.md5(content).hexdigest()
    sha256_str = hashlib.sha256(content).hexdigest()
    hashes = {
        "md5": md5_str,
        "sha256": sha256_str,
    }

    metadata = extract_metadata(file_path, file.filename, size_bytes=size_bytes)
    file_type = detect_file_type(file_path)
    pe_header = analyze_pe_header(file_path)
    imports = analyze_imports(file_path)
    urls_ips = detect_urls_ips(file_path, content=content)
    yara_results = run_yara(file_path, content=content)

    analysis_report = generate_analysis_report(
        metadata,
        file_type,
        pe_header,
        imports,
        urls_ips,
        yara_results,
        hashes
    )

    ai_analysis = await run_ai_analysis(file_path, pe_header)

    analysis_report["ai_analysis"] = ai_analysis

    REPORTS[unique_filename] = analysis_report

    # Every scan is recorded, scored or not - see record_detection().
    detection = None
    try:
        detection = record_detection(
            db,
            metadata=metadata,
            hashes=hashes,
            ai_analysis=ai_analysis,
            yara_results=yara_results,
            urls_ips=urls_ips,
            analysis_report=analysis_report,
        )
    except Exception:
        # A recording failure must not lose the user's analysis result.
        logger.exception(
            "Failed to record detection for %s; returning the analysis anyway.",
            file.filename,
        )

    return {
        "message": "File uploaded successfully",
        "original_filename": file.filename,
        "stored_filename": unique_filename,
        "report_url": f"/api/v1/report/{unique_filename}",
        "hashes": hashes,
        "metadata": metadata,
        "file_type": file_type,
        "pe_header": pe_header,
        "imports": imports,
        "urls_ips": urls_ips,
        "yara_results": yara_results,
        "ai_analysis": ai_analysis,
        "detection": detection,
    }

@router.get("/report/{stored_filename}")
def get_analysis_report(stored_filename: str):

    report = REPORTS.get(stored_filename)

    if report is None:
        raise HTTPException(
            status_code=404,
            detail="Report not found"
        )

    return report