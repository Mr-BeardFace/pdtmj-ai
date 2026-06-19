"""
AWS enumeration and assessment via the AWS CLI.
Useful for cloud pentests, misconfiguration discovery, and credential testing.
"""
import json
import shlex
import shutil
import subprocess
from core import proc as runner
from typing import Optional


def awscli(service: str, command: str, region: Optional[str] = None,
           profile: Optional[str] = None, output: str = "json",
           flags: Optional[str] = None) -> dict:
    if not shutil.which("aws"):
        return {"error": "aws CLI not found. Install: apt install awscli or pip install awscli"}

    cmd = ["aws", service] + shlex.split(command)

    if region:
        cmd += ["--region", region]
    if profile:
        cmd += ["--profile", profile]

    cmd += ["--output", output]

    if flags:
        cmd += shlex.split(flags)

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return {"error": "aws CLI timed out"}

    stdout = proc.stdout.strip()
    stderr = proc.stderr.strip()

    # Try to parse JSON output
    parsed = None
    if output == "json" and stdout:
        try:
            parsed = json.loads(stdout)
        except json.JSONDecodeError:
            pass

    return {
        "service":    service,
        "command":    command,
        "success":    proc.returncode == 0,
        "data":       parsed if parsed else stdout[:16000],
        "error":      stderr[:500] if proc.returncode != 0 else None,
        "_command":   " ".join(cmd),
    }


TOOL_DEFINITION = {
    "name": "awscli",
    "description": (
        "AWS enumeration and security testing via the AWS CLI. "
        "Requires AWS credentials in environment (AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY) "
        "or configured profile (~/.aws/credentials).\n\n"
        "Common security enumeration commands:\n"
        "service='sts' command='get-caller-identity' — verify current identity and permissions\n"
        "service='s3' command='ls' — list accessible S3 buckets\n"
        "service='s3api' command='get-bucket-acl --bucket BUCKETNAME' — check bucket ACL\n"
        "service='s3api' command='list-objects --bucket BUCKETNAME' — list bucket contents\n"
        "service='iam' command='list-users' — enumerate IAM users\n"
        "service='iam' command='list-roles' — enumerate IAM roles\n"
        "service='iam' command='get-account-password-policy' — check password policy\n"
        "service='ec2' command='describe-instances' — list EC2 instances\n"
        "service='ec2' command='describe-security-groups' — check SGs for 0.0.0.0/0 rules\n"
        "service='secretsmanager' command='list-secrets' — enumerate Secrets Manager\n"
        "service='lambda' command='list-functions' — list Lambda functions\n"
        "service='rds' command='describe-db-instances' — list RDS instances\n\n"
        "For unauthenticated checks: test public S3 buckets without credentials."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "service": {"type": "string", "description": "AWS service: s3, iam, ec2, sts, rds, lambda, secretsmanager, etc."},
            "command": {"type": "string", "description": "AWS CLI command and arguments, e.g. 'ls' or 'get-caller-identity' or 'describe-instances --filters Name=instance-state-name,Values=running'"},
            "region":  {"type": "string", "description": "AWS region, e.g. 'us-east-1'. Omit to use default."},
            "profile": {"type": "string", "description": "AWS CLI profile name from ~/.aws/credentials"},
            "output":  {"type": "string", "description": "Output format: json (default), text, table"},
            "flags":   {"type": "string", "description": "Additional AWS CLI flags"},
        },
        "required": ["service", "command"],
    },
}
