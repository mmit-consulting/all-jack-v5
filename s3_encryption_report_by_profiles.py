#!/usr/bin/env python3
"""
s3_encryption_report_by_profiles.py

- Iterates over all local AWS profiles (from ~/.aws/config and ~/.aws/credentials)
- For each profile:
  - Lists S3 buckets
  - Gets bucket region
  - Checks encryption-at-rest (GetBucketEncryption)
    - Disabled if no encryption configuration
    - Enabled + reports SSE algorithm (AES256 or aws:kms) + KMS key id/arn (if any)
- Writes a CSV report whose filename includes the generation date (only in title, not per row)

Usage:
  pip install boto3
  python s3_encryption_report_by_profiles.py
  python s3_encryption_report_by_profiles.py --output-dir . --filename-prefix s3_encryption_report
"""

import argparse
import csv
import datetime as dt
import os
from typing import Dict, List, Set, Tuple

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, ProfileNotFound


def generation_date_str() -> str:
    return dt.datetime.now().strftime("%Y-%m-%d")


def load_all_profiles() -> List[str]:
    """
    Discover all profiles configured locally.
    boto3 session.available_profiles reads shared config/credentials.
    """
    base = boto3.session.Session()
    profiles = list(base.available_profiles)

    # Sometimes "default" isn't listed; include it if it might be usable.
    if "default" not in profiles:
        profiles.append("default")

    # Deduplicate, preserve order
    seen: Set[str] = set()
    out: List[str] = []
    for p in profiles:
        if p and p not in seen:
            out.append(p)
            seen.add(p)
    return out


def create_session(profile: str) -> boto3.session.Session:
    return boto3.session.Session(profile_name=profile)


def get_account_id(session: boto3.session.Session) -> str:
    """
    Best effort: returns account id or '-'
    """
    try:
        sts = session.client("sts", config=Config(retries={"max_attempts": 10, "mode": "standard"}))
        return sts.get_caller_identity().get("Account", "-")
    except Exception:
        return "-"


def list_buckets(s3_client) -> List[str]:
    resp = s3_client.list_buckets()
    return [b["Name"] for b in resp.get("Buckets", [])]


def get_bucket_region(s3_client, bucket: str) -> str:
    """
    GetBucketLocation returns None/'' for us-east-1.
    """
    resp = s3_client.get_bucket_location(Bucket=bucket)
    loc = resp.get("LocationConstraint")
    return "us-east-1" if not loc else loc


def get_bucket_encryption(s3_client, bucket: str) -> Tuple[str, str, str]:
    """
    Returns (encryption_status, sse_algorithm, kms_key_id_or_arn)

    encryption_status:
      - Enabled
      - Disabled
      - Error

    sse_algorithm:
      - AES256
      - aws:kms
      - -

    kms_key_id_or_arn:
      - key id/arn if aws:kms
      - -
      - or error code (internal) when status=Error
    """
    try:
        resp = s3_client.get_bucket_encryption(Bucket=bucket)
        rules = resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        if not rules:
            return ("Disabled", "-", "-")

        rule0 = rules[0]
        by_default = rule0.get("ApplyServerSideEncryptionByDefault", {}) or {}
        sse_alg = by_default.get("SSEAlgorithm", "-")

        if sse_alg == "aws:kms":
            kms_key = by_default.get("KMSMasterKeyID", "-") or "-"
        else:
            kms_key = "-"

        return ("Enabled", sse_alg, kms_key)

    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "") or "UnknownClientError"
        # This is the expected error when encryption isn't configured
        if code == "ServerSideEncryptionConfigurationNotFoundError":
            return ("Disabled", "-", "-")
        return ("Error", "-", code)
    except Exception:
        return ("Error", "-", "UnknownError")


def write_csv(path: str, rows: List[Dict[str, str]]) -> None:
    headers = [
        "profile",
        "account_id",
        "bucket",
        "region",
        "encryption_status",
        "sse_algorithm",
        "kms_key_id",
        "error",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        for r in rows:
            w.writerow({h: r.get(h, "") for h in headers})


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Report S3 bucket encryption-at-rest status across all local AWS profiles."
    )
    parser.add_argument("--output-dir", default=".", help="Directory to write the CSV report into")
    parser.add_argument("--filename-prefix", default="s3_encryption_report", help="CSV filename prefix")
    args = parser.parse_args()

    gen_date = generation_date_str()
    out_path = os.path.join(args.output_dir, f"{args.filename_prefix}_{gen_date}.csv")

    profiles = load_all_profiles()
    rows: List[Dict[str, str]] = []

    for profile in profiles:
        # Create session
        try:
            session = create_session(profile)
        except ProfileNotFound:
            rows.append({
                "profile": profile,
                "account_id": "-",
                "bucket": "-",
                "region": "-",
                "encryption_status": "Error",
                "sse_algorithm": "-",
                "kms_key_id": "-",
                "error": "ProfileNotFound",
            })
            continue

        account_id = get_account_id(session)
        s3 = session.client("s3", config=Config(retries={"max_attempts": 10, "mode": "standard"}))

        # List buckets
        try:
            buckets = list_buckets(s3)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "") or "UnknownClientError"
            rows.append({
                "profile": profile,
                "account_id": account_id,
                "bucket": "-",
                "region": "-",
                "encryption_status": "Error",
                "sse_algorithm": "-",
                "kms_key_id": "-",
                "error": f"ListBucketsFailed:{code}",
            })
            continue

        # No buckets case
        if not buckets:
            rows.append({
                "profile": profile,
                "account_id": account_id,
                "bucket": "(no buckets)",
                "region": "-",
                "encryption_status": "-",
                "sse_algorithm": "-",
                "kms_key_id": "-",
                "error": "",
            })
            continue

        # Per bucket checks
        for bucket in buckets:
            region = "-"
            error = ""

            try:
                region = get_bucket_region(s3, bucket)
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "") or "UnknownClientError"
                error = f"GetBucketLocationFailed:{code}"

            status, sse_alg, kms_key_or_err = get_bucket_encryption(s3, bucket)

            kms_key_id = "-"
            if status == "Error":
                # kms_key_or_err is an error code in this case
                error = error or f"GetBucketEncryptionFailed:{kms_key_or_err}"
            else:
                kms_key_id = kms_key_or_err

            rows.append({
                "profile": profile,
                "account_id": account_id,
                "bucket": bucket,
                "region": region,
                "encryption_status": status,     # Enabled/Disabled/Error
                "sse_algorithm": sse_alg,        # AES256/aws:kms/-
                "kms_key_id": kms_key_id,        # key id/arn or -
                "error": error,
            })

    # Write report
    os.makedirs(args.output_dir, exist_ok=True)
    write_csv(out_path, rows)
    print(f"[OK] Wrote report to: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
