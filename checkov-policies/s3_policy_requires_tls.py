"""Custom Checkov policy for VULN #4 (part 2 of 2).

Fails an aws_s3_bucket_policy unless it has a Deny statement for requests
where aws:SecureTransport is false (CIS AWS Foundations v1.4.0 2.1.2; 2.1.1
in v3.0 and v5.0). Part 1 (s3_bucket_has_policy.yaml) makes sure every
bucket has a policy for this check to look at.
"""
import ast
import json
import re

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


def _as_document(raw):
    """Turn Checkov's view of a `policy` attribute into a dict, or None.

    Depending on how much Checkov could evaluate, the value arrives as a
    dict, a JSON string, or the unevaluated text `jsonencode({...})` with
    Terraform references left as "${...}" strings.
    """
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    if text.startswith("${") and text.endswith("}"):
        text = text[2:-1]
    if text.startswith("jsonencode(") and text.endswith(")"):
        text = text[len("jsonencode("):-1]
    # Checkov sometimes renders a Terraform reference inside a string with
    # extra quotes: "${ref}" as ''ref'' and "${ref}/path" as ''ref'/path'.
    # Collapse the doubled quotes, then rejoin 'ref'/path' into one string.
    repaired = text.replace("''", "'")
    repaired = re.sub(r"'([\w.\-]+)'(/[^']*)'", r"'\1\2'", repaired)
    candidates = [text, repaired]
    for candidate in candidates:
        for parse in (json.loads, ast.literal_eval):
            try:
                doc = parse(candidate)
            except (ValueError, SyntaxError):
                continue
            if isinstance(doc, dict):
                return doc
    return None


def _denies_insecure_transport(statement):
    if statement.get("Effect") != "Deny":
        return False
    actions = statement.get("Action", [])
    actions = actions if isinstance(actions, list) else [actions]
    if not {"s3:*", "*"} & set(actions):
        return False
    principal = statement.get("Principal")
    if principal != "*" and not (isinstance(principal, dict) and principal.get("AWS") == "*"):
        return False
    value = statement.get("Condition", {}).get("Bool", {}).get("aws:SecureTransport")
    return str(value).lower() == "false"


class S3PolicyRequiresTLS(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure S3 bucket policies deny requests that don't use TLS",
            id="CKV_F2_2",
            categories=[CheckCategories.NETWORKING],
            supported_resources=["aws_s3_bucket_policy"],
        )

    def scan_resource_conf(self, conf):
        doc = _as_document(conf.get("policy"))
        if doc is None:
            # Fail closed: a policy this check can't read is not proof of
            # TLS-only access. If a Checkov upgrade changes how policies are
            # rendered, CI goes red instead of silently passing.
            self.details.append("could not parse the policy document")
            return CheckResult.FAILED
        statements = doc.get("Statement", [])
        statements = statements if isinstance(statements, list) else [statements]
        if any(_denies_insecure_transport(s) for s in statements):
            return CheckResult.PASSED
        return CheckResult.FAILED


check = S3PolicyRequiresTLS()
