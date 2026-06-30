"""
MSSQL interaction via impacket's mssqlclient.py.
Runs a single SQL statement or OS command (xp_cmdshell) non-interactively.
"""
import shlex
import shutil
import subprocess
from core import proc as runner
import tempfile
from typing import Optional


def impacket_mssql(target: str, username: str, password: Optional[str] = None,
                   hash: Optional[str] = None, domain: Optional[str] = None,
                   query: Optional[str] = None, xp_cmdshell: Optional[str] = None,
                   port: int = 1433, flags: Optional[str] = None) -> dict:
    binary = shutil.which("mssqlclient.py") or shutil.which("impacket-mssqlclient")
    if not binary:
        return {"error": "mssqlclient.py not found. Install impacket."}

    if not query and not xp_cmdshell:
        # Default: get version and basic info
        query = "SELECT @@VERSION; SELECT SYSTEM_USER; SELECT IS_SRVROLEMEMBER('sysadmin');"

    # Build the SQL to run
    sql_statements = []
    if query:
        sql_statements.append(query)
    if xp_cmdshell:
        sql_statements.append("EXEC xp_cmdshell 'whoami';")  # first enable if needed
        sql_statements.append(f"EXEC xp_cmdshell '{xp_cmdshell}';")

    # Write SQL to temp file so we can pipe it
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sql", delete=False) as f:
        for stmt in sql_statements:
            f.write(stmt + "\n")
        f.write("exit\n")
        sql_file = f.name

    # impacket's mssqlclient has NO password flag — the password goes INSIDE the
    # target string (user:pass@host). A lone -p is silently abbreviated to -port by
    # argparse, overwriting the real port with the password, then int(port) explodes.
    auth = f"{username}:{password}" if password else username
    target_str = f"{domain}/{auth}@{target}" if domain else f"{auth}@{target}"

    cmd = [binary, target_str, "-port", str(port)]
    if hash:
        cmd += ["-hashes", hash]
    # A domain account authenticates to MSSQL over Windows/NTLM, not SQL auth.
    if domain and "-windows-auth" not in (flags or ""):
        cmd += ["-windows-auth"]
    if flags:
        cmd += shlex.split(flags)

    try:
        with open(sql_file) as stdin_f:
            proc = runner.run(
                cmd, stdin=stdin_f, capture_output=True, text=True, timeout=60
            )
    except subprocess.TimeoutExpired:
        return {"error": "mssqlclient.py timed out"}
    finally:
        import os
        try:
            os.unlink(sql_file)
        except Exception:
            pass

    output = proc.stdout + proc.stderr
    cmd_str = " ".join(cmd) + f" < {sql_file}"

    return {
        "target":      f"{target}:{port}",
        "username":    username,
        "output":      output[:16000],
        "success":     proc.returncode == 0,
        "_command":    cmd_str,
    }


TOOL_DEFINITION = {
    "name": "impacket_mssql",
    "description": (
        "Interact with Microsoft SQL Server via impacket's mssqlclient. "
        "Run arbitrary SQL queries or OS commands via xp_cmdshell. "
        "Automatically retrieves version, current user, and sysadmin status if no query given. "
        "For xp_cmdshell: if disabled, attempt 'sp_configure xp_cmdshell 1' first (requires sysadmin). "
        "Use to: enumerate databases/tables, read files (BULK INSERT), execute OS commands."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target":      {"type": "string", "description": "MSSQL server IP or hostname"},
            "username":    {"type": "string", "description": "SQL or Windows username"},
            "password":    {"type": "string", "description": "Password"},
            "hash":        {"type": "string", "description": "NTLM hash for pass-the-hash (LMHASH:NTHASH)"},
            "domain":      {"type": "string", "description": "Windows domain for Windows auth"},
            "query":       {"type": "string", "description": "SQL query to execute, e.g. 'SELECT name FROM master.dbo.sysdatabases'"},
            "xp_cmdshell": {"type": "string", "description": "OS command to run via xp_cmdshell, e.g. 'whoami /all'"},
            "port":        {"type": "integer", "description": "MSSQL port. Default: 1433"},
            "flags":       {"type": "string", "description": "Additional mssqlclient.py flags, e.g. '-windows-auth'"},
        },
        "required": ["target", "username"],
    },
}
