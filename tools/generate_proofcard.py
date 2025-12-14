#!/usr/bin/env python3
"""tools/generate_proofcard.py

Generate a τGuardian ProofCard JSON from an enriched JSONL file.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

def _load_record(enriched_path: Path, instance_id: Optional[str]) -> Dict[str, Any]:
    if not enriched_path.exists():
        raise FileNotFoundError(f"enriched-path not found: {enriched_path}")

    with enriched_path.open("r", encoding="utf-8") as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln:
                continue
            rec = json.loads(ln)
            if instance_id is None:
                return rec
            if rec.get("instance_id") == instance_id:
                return rec

    if instance_id is None:
        raise ValueError(f"No JSON records found in enriched-path: {enriched_path}")
    raise ValueError(
        f"No record found for instance_id={instance_id!r} in {enriched_path}"
    )

def _compute_patch_hash(record: Dict[str, Any]) -> Optional[str]:
    patch = record.get("patch")
    if not patch:
        return None
    if not isinstance(patch, str):
        patch = str(patch)
    return hashlib.sha256(patch.encode("utf-8")).hexdigest()

def _compute_hmac_signature(payload_bytes: bytes, key_path: Path) -> str:
    key = key_path.read_bytes()
    sig = hmac.new(key, payload_bytes, hashlib.sha256).hexdigest()
    return sig

def generate_proofcard(
    enriched_path: Path,
    out_dir: Path,
    instance_id: Optional[str] = None,
    sign_key_path: Optional[Path] = None,
) -> Path:
    import uuid

    out_dir.mkdir(parents=True, exist_ok=True)

    rec = _load_record(enriched_path, instance_id=instance_id)

    run_id = rec.get("run_id", "unknown_run")
    resolved_instance_id = rec.get("instance_id") or rec.get("task") or "unknown_instance"
    model = rec.get("model", "unknown_model")

    tests_passed = rec.get("tests_passed", 0)
    tests_failed = rec.get("tests_failed", 0)
    total_tests = rec.get("total_tests", tests_passed + tests_failed)

    cri = rec.get("cri", None)
    sad_flag = rec.get("sad_flag", rec.get("sad", None))
    tau = rec.get("tau", rec.get("last_tau", None))
    decision = rec.get("final_decision", rec.get("decision", "UNKNOWN"))

    patch_hash = _compute_patch_hash(rec)

    proofcard_id = str(uuid.uuid4())
    now_utc = datetime.now(timezone.utc).isoformat()

    payload: Dict[str, Any] = {
        "proofcard_id": proofcard_id,
        "run_id": run_id,
        "instance_id": resolved_instance_id,
        "model": model,
        "timestamp": now_utc,
        "tests": {
            "passed": tests_passed,
            "failed": tests_failed,
            "total": total_tests,
        },
        "cri": cri,
        "sad_flag": sad_flag,
        "tau": tau,
        "decision": decision,
        "patch_hash": patch_hash,
        "source_enriched_path": str(enriched_path),
    }

    payload_bytes = _canonical_json_bytes(payload)
    payload_hash = hashlib.sha256(payload_bytes).hexdigest()
    payload["payload_hash"] = payload_hash

    if sign_key_path is not None:
        if not sign_key_path.exists():
            raise FileNotFoundError(f"sign-key not found: {sign_key_path}")
        signature = _compute_hmac_signature(payload_bytes, sign_key_path)
        payload["signature"] = {
            "algo": "HMAC-SHA256",
            "key_hint": sign_key_path.name,
            "value": signature,
        }

    out_path = out_dir / "ProofCard.json"
    out_path.write_text(
        json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(f"[generate_proofcard] Wrote ProofCard to {out_path}")
    return out_path

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a τGuardian ProofCard from enriched JSONL."
    )
    parser.add_argument(
        "--enriched-path",
        required=True,
        help="Path to enriched JSONL file (output of analyze_mini_swe_results.py).",
    )
    parser.add_argument(
        "--out-dir",
        required=True,
        help="Directory to write ProofCard.json into.",
    )
    parser.add_argument(
        "--instance-id",
        default=None,
        help="Optional instance_id to select a specific record (default: first record).",
    )
    parser.add_argument(
        "--sign-key",
        default=None,
        help="Optional path to secret key file for HMAC-SHA256 signature.",
    )
    args = parser.parse_args()

    enriched_path = Path(args.enriched_path).resolve()
    out_dir = Path(args.out_dir).resolve()
    instance_id = args.instance_id
    sign_key_path = Path(args.sign_key).resolve() if args.sign_key else None

    generate_proofcard(
        enriched_path,
        out_dir,
        instance_id=instance_id,
        sign_key_path=sign_key_path,
    )

if __name__ == "__main__":
    main()
