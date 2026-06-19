import shlex
import shutil
import subprocess
from core import proc as runner
from typing import Optional


def mongosh_query(target: str, port: int = 27017, database: str = "admin",
                  command: str = "db.adminCommand({listDatabases:1})",
                  username: Optional[str] = None, password: Optional[str] = None,
                  flags: Optional[str] = None) -> dict:
    binary = shutil.which("mongosh") or shutil.which("mongo")
    if not binary:
        return {"error": "mongosh (or mongo) not found in PATH"}

    if username and password:
        uri = f"mongodb://{username}:{password}@{target}:{port}/{database}"
    else:
        uri = f"mongodb://{target}:{port}/{database}"

    cmd = [binary, uri, "--quiet", "--eval", command]
    if flags:
        cmd += shlex.split(flags)

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return {"error": "mongosh timed out"}

    output = (proc.stdout + proc.stderr).strip()
    return {
        "target":    f"{target}:{port}",
        "database":  database,
        "command":   command,
        "output":    output[:16000],
        "success":   proc.returncode == 0,
        "_command":  " ".join(cmd),
    }


TOOL_DEFINITION = {
    "name": "mongosh_query",
    "description": (
        "Run JavaScript commands against a MongoDB instance via mongosh. "
        "Use to: list databases, enumerate collections, read documents, check auth configuration. "
        "If unauthenticated: test 'db.adminCommand({listDatabases:1})' and 'show collections'. "
        "Common recon commands: "
        "'db.adminCommand({listDatabases:1})' — list all databases; "
        "'db.getCollectionNames()' — list collections; "
        "'db.users.find().limit(5)' — read user records."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target":   {"type": "string", "description": "MongoDB server IP or hostname"},
            "port":     {"type": "integer", "description": "MongoDB port. Default: 27017"},
            "database": {"type": "string", "description": "Database to connect to. Default: admin"},
            "command":  {"type": "string", "description": "JavaScript command to execute. Default: list databases"},
            "username": {"type": "string", "description": "MongoDB username"},
            "password": {"type": "string", "description": "MongoDB password"},
            "flags":    {"type": "string", "description": "Additional mongosh flags"},
        },
        "required": ["target"],
    },
}
