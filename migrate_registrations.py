#!/usr/bin/env python3
"""
Migrate CrowdStrike AWS account registrations from CSPMRegistration to CloudAWSRegistration.

For each secret provided:
  1. Read OUs from the secret
  2. List all AWS accounts in those OUs (recursive)
  3. Check each account for an existing CloudAWSRegistration
  4. If registered: deregister, re-register using the new method, then update the
     corresponding StackSet's ExternalID parameter and push to stack instances

Usage:
    python migrate_registrations.py --secrets CrowdStrikeAPISecret-A CrowdStrikeAPISecret-B \\
        --stackset-admin-role arn:aws:iam::123456789012:role/CrowdStrikeStackSetAdministrationRole \\
        --stackset-exec-role CrowdStrikeStackSetExecutionRole \\
        --enable-ioa --identity-protection

    # Dry-run first (recommended):
    python migrate_registrations.py --secrets CrowdStrikeAPISecret-A \\
        --stackset-admin-role arn:aws:iam::123456789012:role/CrowdStrikeStackSetAdministrationRole \\
        --stackset-exec-role CrowdStrikeStackSetExecutionRole \\
        --enable-ioa --dry-run

    # Target specific accounts only:
    python migrate_registrations.py --secrets CrowdStrikeAPISecret-A \\
        --stackset-admin-role arn:aws:iam::123456789012:role/CrowdStrikeStackSetAdministrationRole \\
        --stackset-exec-role CrowdStrikeStackSetExecutionRole \\
        --accounts 123456789012 987654321098 --enable-ioa
"""

import argparse
import base64
import datetime
import json
import logging
import sys
from typing import Optional

import boto3
from botocore.exceptions import ClientError

try:
    from falconpy import CloudAWSRegistration
except ImportError:
    print("ERROR: falconpy not available. Install with: pip install crowdstrike-falconpy")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# AWS helpers — Secrets Manager
# ---------------------------------------------------------------------------

def get_secret(secret_name: str, region: str) -> dict:
    """Retrieve and parse a Secrets Manager secret."""
    client = boto3.client("secretsmanager", region_name=region)
    try:
        resp = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        raise RuntimeError(f"Failed to retrieve secret '{secret_name}': {e}") from e

    raw = resp.get("SecretString") or base64.b64decode(resp["SecretBinary"]).decode()
    secret = json.loads(raw)

    for field in ("FalconClientId", "FalconSecret", "FalconCloud", "OUs"):
        if field not in secret:
            raise ValueError(f"Secret '{secret_name}' missing required field: {field}")

    return secret


# ---------------------------------------------------------------------------
# AWS helpers — Organizations
# ---------------------------------------------------------------------------

def get_accounts_in_ou(ou_id: str, nested: bool = True) -> list[str]:
    """Return all AWS account IDs under an OU, optionally recursive."""
    client = boto3.client("organizations")
    accounts = []
    paginator = client.get_paginator("list_children")

    for page in paginator.paginate(ParentId=ou_id, ChildType="ACCOUNT"):
        accounts.extend(child["Id"] for child in page.get("Children", []))

    if nested:
        for page in paginator.paginate(ParentId=ou_id, ChildType="ORGANIZATIONAL_UNIT"):
            for child_ou in page.get("Children", []):
                accounts.extend(get_accounts_in_ou(child_ou["Id"], nested=True))

    return accounts


def get_accounts_for_ous(ou_list: str, nested: bool = True) -> list[str]:
    """Return deduplicated account IDs for a comma-separated OU list."""
    ous = [ou.strip() for ou in ou_list.split(",") if ou.strip()]
    all_accounts = []
    for ou in ous:
        logger.info(f"  Scanning OU: {ou}")
        try:
            found = get_accounts_in_ou(ou, nested=nested)
            logger.info(f"    Found {len(found)} account(s)")
            all_accounts.extend(found)
        except ClientError as e:
            logger.error(f"    Failed to list accounts for OU {ou}: {e}")
    return list(dict.fromkeys(all_accounts))  # deduplicate, preserve order


# ---------------------------------------------------------------------------
# AWS helpers — CloudFormation StackSets
# ---------------------------------------------------------------------------

def get_stackset_name(account_id: str) -> str:
    return f"CrowdStrike-Cloud-Security-Stackset-{account_id}"


def get_stackset_parameters(cf_client, stackset_name: str) -> Optional[list[dict]]:
    """Return the current Parameters list for a StackSet, or None if not found."""
    try:
        resp = cf_client.describe_stack_set(StackSetName=stackset_name)
        return resp["StackSet"].get("Parameters", [])
    except cf_client.exceptions.StackSetNotFoundException:
        return None
    except ClientError as e:
        logger.error(f"    Failed to describe StackSet {stackset_name}: {e}")
        return None


def get_stackset_tags(cf_client, stackset_name: str) -> list[dict]:
    try:
        resp = cf_client.describe_stack_set(StackSetName=stackset_name)
        return resp["StackSet"].get("Tags", [])
    except ClientError as e:
        logger.warning(f"    Failed to get tags for {stackset_name}: {e}")
        return []


def get_stackset_template_url(cf_client, stackset_name: str) -> Optional[str]:
    """Return the template_url tag value from the StackSet, or None."""
    for tag in get_stackset_tags(cf_client, stackset_name):
        if tag.get("Key") == "template_url":
            return tag.get("Value")
    return None


def list_stackset_accounts(cf_client, stackset_name: str) -> list[str]:
    """Return all AWS account IDs that have instances in this StackSet."""
    accounts = []
    paginator = cf_client.get_paginator("list_stack_instances")
    for page in paginator.paginate(StackSetName=stackset_name):
        accounts.extend(
            inst["Account"]
            for inst in page.get("Summaries", [])
        )
    return list(set(accounts))


def update_stackset_external_id(
    account_id: str,
    new_external_id: str,
    admin_role_arn: str,
    exec_role_name: str,
    region: str,
    dry_run: bool,
) -> bool:
    """
    Update the ExternalID parameter on the base CSPM StackSet for account_id and
    push the change to all stack instances.

    All other parameters are kept at their current values (UsePreviousValue=True).
    Returns True on success.
    """
    stackset_name = get_stackset_name(account_id)
    cf_client = boto3.client("cloudformation", region_name=region)

    # Confirm the StackSet exists and fetch its current parameters
    current_params = get_stackset_parameters(cf_client, stackset_name)
    if current_params is None:
        logger.warning(f"    StackSet {stackset_name} not found — skipping StackSet update")
        return False

    # Confirm ExternalID is actually a parameter on this StackSet
    param_keys = {p["ParameterKey"] for p in current_params}
    if "ExternalID" not in param_keys:
        logger.warning(
            f"    StackSet {stackset_name} has no ExternalID parameter — skipping StackSet update"
        )
        return False

    old_external_id = next(
        (p["ParameterValue"] for p in current_params if p["ParameterKey"] == "ExternalID"),
        "<unknown>",
    )
    logger.info(f"    StackSet ExternalID: {old_external_id} -> {new_external_id}")

    if dry_run:
        logger.info(f"    [dry-run] Would update StackSet {stackset_name} ExternalID")
        return True

    template_url = get_stackset_template_url(cf_client, stackset_name)
    if not template_url:
        logger.error(f"    No template_url tag on {stackset_name} — cannot update StackSet")
        return False

    stackset_tags = get_stackset_tags(cf_client, stackset_name)

    # Build parameter list: override ExternalID, keep everything else unchanged
    new_params = []
    for p in current_params:
        if p["ParameterKey"] == "ExternalID":
            new_params.append({"ParameterKey": "ExternalID", "ParameterValue": new_external_id})
        else:
            new_params.append({"ParameterKey": p["ParameterKey"], "UsePreviousValue": True})

    timestamp = datetime.datetime.now().strftime("%m%d%y%H%M%S")

    try:
        cf_client.update_stack_set(
            StackSetName=stackset_name,
            TemplateURL=template_url,
            Parameters=new_params,
            Capabilities=["CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"],
            AdministrationRoleARN=admin_role_arn,
            ExecutionRoleName=exec_role_name,
            Tags=stackset_tags,
            OperationId=f"{account_id}-extid-{timestamp}",
            OperationPreferences={
                "FailureTolerancePercentage": 100,
                "MaxConcurrentPercentage": 100,
                "ConcurrencyMode": "SOFT_FAILURE_TOLERANCE",
            },
        )
        logger.info(f"    StackSet {stackset_name} update initiated")
        return True
    except ClientError as e:
        logger.error(f"    Failed to update StackSet {stackset_name}: {e}")
        return False


# ---------------------------------------------------------------------------
# CrowdStrike helpers
# ---------------------------------------------------------------------------

def build_falcon(creds: dict) -> CloudAWSRegistration:
    return CloudAWSRegistration(
        client_id=creds["FalconClientId"],
        client_secret=creds["FalconSecret"],
        base_url=creds["FalconCloud"],
    )


def check_registration(falcon: CloudAWSRegistration, account_id: str) -> Optional[dict]:
    """Return the registration resource dict if the account is registered, else None."""
    resp = falcon.get_accounts(ids=account_id)
    if resp.get("status_code") == 200:
        resources = resp.get("body", {}).get("resources", [])
        if resources:
            return resources[0]
    return None


def extract_iam_role_arn(resource: dict) -> Optional[str]:
    """Extract the IAM role ARN from a get_accounts resource dict."""
    return resource.get("resource_metadata", {}).get("iam_role_arn") or None


def deregister(falcon: CloudAWSRegistration, account_id: str, dry_run: bool) -> bool:
    """Delete the account registration. Returns True on success."""
    if dry_run:
        logger.info(f"    [dry-run] Would deregister {account_id}")
        return True

    resp = falcon.delete_account(ids=account_id)
    code = resp.get("status_code")
    if code in (200, 204):
        logger.info(f"    Deregistered {account_id} (status {code})")
        return True

    errors = resp.get("body", {}).get("errors", [])
    logger.error(f"    Failed to deregister {account_id} (status {code}): {errors}")
    return False


def build_products(opts: argparse.Namespace) -> tuple[list[dict], bool]:
    """
    Build the products list and csp_events flag from CLI options.

    CSPM product features (all under one 'cspm' product):
        iom                  - asset inventory (always on)
        ioa                  - realtime visibility / indicators of attack
        sensormgmt           - 1-click sensor management
        dspm                 - data security posture management
        vulnerability_scanning

    IDP is a separate product with features=["default"].
    csp_events must be True when ioa or idp is active.
    """
    cspm_features = ["iom"]
    if opts.enable_ioa:
        cspm_features.append("ioa")
    if opts.sensor_management:
        cspm_features.append("sensormgmt")
    if opts.enable_dspm:
        cspm_features.append("dspm")
    if opts.enable_vulnerability_scanning:
        cspm_features.append("vulnerability_scanning")

    products = [{"features": cspm_features, "product": "cspm"}]

    if opts.identity_protection:
        products.append({"features": ["default"], "product": "idp"})

    csp_events = opts.enable_ioa or opts.identity_protection
    return products, csp_events


def register(
    falcon: CloudAWSRegistration,
    account_id: str,
    account_type: str,
    products: list[dict],
    csp_events: bool,
    dry_run: bool,
    iam_role_arn: Optional[str] = None,
) -> Optional[str]:
    """
    Register an account.
    Returns the new external_id on success, None on failure.
    In dry-run mode returns the sentinel string 'dry-run'.
    """
    if dry_run:
        role_info = f" iam_role_arn={iam_role_arn}" if iam_role_arn else ""
        logger.info(
            f"    [dry-run] Would register {account_id} "
            f"products={json.dumps(products)} csp_events={csp_events}{role_info}"
        )
        return "dry-run"

    # Build body manually — the falconpy keyword builder for this service
    # does not expose iam_role_arn or deployment_method.
    resource: dict = {
        "account_id": account_id,
        "account_type": account_type,
        "csp_events": csp_events,
        "deployment_method": "cft",
        "products": products,
    }
    if iam_role_arn:
        resource["iam_role_arn"] = iam_role_arn

    resp = falcon.create_account(body={"resources": [resource]})
    code = resp.get("status_code")
    if code in (200, 201):
        resp_resource = resp.get("body", {}).get("resources", [{}])[0]
        # external_id lives under resource_metadata in the new API
        new_external_id = resp_resource.get("resource_metadata", {}).get("external_id")
        if not new_external_id:
            # fallback: some responses surface it at the top level
            new_external_id = resp_resource.get("external_id")
        if not new_external_id:
            logger.error(
                f"    Registration succeeded but external_id missing from response. "
                f"Raw resource keys: {list(resp_resource.keys())}"
            )
            return None
        role_info = f" iam_role_arn={iam_role_arn}" if iam_role_arn else ""
        logger.info(f"    Registered {account_id} (status {code}) external_id={new_external_id}{role_info}")
        return new_external_id

    errors = resp.get("body", {}).get("errors", [])
    logger.error(f"    Failed to register {account_id} (status {code}): {errors}")
    return None


# ---------------------------------------------------------------------------
# Per-account processing
# ---------------------------------------------------------------------------

def process_account(
    account_id: str,
    falcon: CloudAWSRegistration,
    account_type: str,
    products: list[dict],
    csp_events: bool,
    dry_run: bool,
    admin_role_arn: str,
    exec_role_name: str,
    cf_region: str,
) -> str:
    """
    Check, deregister, re-register, and update the StackSet ExternalID.
    Returns one of: 'migrated', 'failed', 'skipped'.
    """
    logger.info(f"  Processing account: {account_id}")

    existing = check_registration(falcon, account_id)

    if existing:
        iam_role_arn = extract_iam_role_arn(existing)
        if iam_role_arn:
            logger.info(f"    Found existing IAM role: {iam_role_arn}")
        else:
            logger.warning("    No IAM role ARN found in existing registration")

        logger.info("    Currently registered — deregistering first")
        if not deregister(falcon, account_id, dry_run):
            return "failed"

        new_external_id = register(
            falcon, account_id, account_type, products, csp_events, dry_run, iam_role_arn
        )
        if new_external_id is None:
            return "failed"

        # Update the StackSet so the IAM role trust policy ExternalID matches
        stackset_ok = update_stackset_external_id(
            account_id=account_id,
            new_external_id=new_external_id,
            admin_role_arn=admin_role_arn,
            exec_role_name=exec_role_name,
            region=cf_region,
            dry_run=dry_run,
        )
        if not stackset_ok:
            # Registration succeeded but StackSet update failed — flag as failed so
            # the operator knows the ExternalID mismatch still needs resolving.
            logger.error(
                f"    Registration succeeded but StackSet ExternalID update failed for {account_id}"
            )
            return "failed"

        return "migrated"

    else:
        logger.info("    Not currently registered — skipping")
        return "skipped"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Migrate CrowdStrike AWS account registrations to CloudAWSRegistration"
    )
    p.add_argument(
        "--secrets",
        nargs="+",
        required=True,
        metavar="SECRET_NAME",
        help="One or more Secrets Manager secret names (e.g. CrowdStrikeAPISecret-A)",
    )
    p.add_argument(
        "--region",
        default=None,
        help="AWS region for Secrets Manager and CloudFormation (defaults to boto3 session region)",
    )
    p.add_argument(
        "--accounts",
        nargs="+",
        metavar="ACCOUNT_ID",
        help="Process only these account IDs instead of scanning OUs",
    )
    p.add_argument(
        "--account-type",
        default="commercial",
        choices=["commercial", "gov"],
        help="AWS account type (default: commercial)",
    )
    p.add_argument(
        "--no-nested-ous",
        action="store_true",
        help="Only process direct child accounts of each OU, not nested OUs",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be done without making any API or CloudFormation calls",
    )
    # StackSet role args — required for the ExternalID update step
    p.add_argument(
        "--stackset-admin-role",
        required=True,
        metavar="ARN",
        help="ARN of the StackSet administration role (e.g. arn:aws:iam::ACCOUNT:role/CrowdStrikeStackSetAdministrationRole)",
    )
    p.add_argument(
        "--stackset-exec-role",
        required=True,
        metavar="ROLE_NAME",
        help="Name (not ARN) of the StackSet execution role (e.g. CrowdStrikeStackSetExecutionRole)",
    )
    # Feature flags — mirror the CloudFormation template parameters
    p.add_argument("--enable-ioa", action="store_true", help="Enable IOA / realtime visibility")
    p.add_argument("--identity-protection", action="store_true", help="Enable Identity Protection (IDP)")
    p.add_argument("--sensor-management", action="store_true", help="Enable 1-click sensor management")
    p.add_argument("--enable-dspm", action="store_true", help="Enable DSPM")
    p.add_argument("--enable-vulnerability-scanning", action="store_true", help="Enable vulnerability scanning")

    return p.parse_args()


def main() -> None:
    opts = parse_args()

    session = boto3.Session()
    region = opts.region or session.region_name or "us-east-1"

    products, csp_events = build_products(opts)

    if opts.dry_run:
        logger.info("DRY-RUN mode — no changes will be made")

    logger.info(
        f"Registration config: account_type={opts.account_type} "
        f"csp_events={csp_events} products={json.dumps(products)}"
    )
    logger.info(f"StackSet roles: admin={opts.stackset_admin_role} exec={opts.stackset_exec_role}")

    total = {"migrated": 0, "failed": 0, "skipped": 0}

    for secret_name in opts.secrets:
        logger.info(f"\n=== Secret: {secret_name} ===")

        try:
            creds = get_secret(secret_name, region)
        except Exception as e:
            logger.error(f"  Skipping secret: {e}")
            continue

        falcon = build_falcon(creds)

        if opts.accounts:
            accounts = opts.accounts
            logger.info(f"  Using explicit account list: {accounts}")
        else:
            nested = not opts.no_nested_ous
            logger.info(f"  OUs: {creds['OUs']} (nested={nested})")
            try:
                accounts = get_accounts_for_ous(creds["OUs"], nested=nested)
            except Exception as e:
                logger.error(f"  Failed to list accounts: {e}")
                continue

        logger.info(f"  Accounts to process: {len(accounts)}")

        for account_id in accounts:
            result = process_account(
                account_id=account_id,
                falcon=falcon,
                account_type=opts.account_type,
                products=products,
                csp_events=csp_events,
                dry_run=opts.dry_run,
                admin_role_arn=opts.stackset_admin_role,
                exec_role_name=opts.stackset_exec_role,
                cf_region=region,
            )
            total[result] += 1

    logger.info(
        f"\n=== Summary ===\n"
        f"  Migrated (deregistered + re-registered + StackSet updated): {total['migrated']}\n"
        f"  Failed:                                                     {total['failed']}\n"
        f"  Skipped:                                                    {total['skipped']}"
    )

    if total["failed"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
