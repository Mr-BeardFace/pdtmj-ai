from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from core.timeutil import now_local
import uuid


class TokenUsage(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0


class ToolCall(BaseModel):
    id: str
    tool_name: str
    inputs: Dict[str, Any]
    output: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    command_str: Optional[str] = None   # actual CLI command executed, if applicable
    timestamp: datetime = Field(default_factory=lambda: now_local())


class CvssScores(BaseModel):
    vector: str = ""
    base_score: float = 0.0
    temporal_score: float = 0.0
    environmental_score: float = 0.0


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    type: str                    # recon, vuln, config, exposure
    severity: str                # info, low, medium, high, critical
    title: str
    description: str             # paragraph(s): what it is, why it exists, how exploited
    impact: str = ""             # what breaks + likelihood of exploitation
    target: str
    evidence: Dict[str, Any] = {}
    cvss: Optional[CvssScores] = None
    remediation: List[str] = []  # max 5 bullets
    verified: bool = False
    timestamp: datetime = Field(default_factory=lambda: now_local())


class EngagementRun(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:12])
    agent: str
    target: str
    start_time: datetime = Field(default_factory=lambda: now_local())
    end_time: Optional[datetime] = None
    findings: List[Finding] = []
    tool_calls: List[ToolCall] = []
    status: str = "running"      # running, complete, failed
    technical_overview: Optional[str] = None
    executive_summary: Optional[str] = None
    summary: Optional[str] = None
    token_usage: TokenUsage = Field(default_factory=TokenUsage)
    estimated_cost_usd: float = 0.0


class Surface(BaseModel):
    """An attack surface — the unit the Enum→Plan→Exploit→Validate loop cycles on.

    A surface is a (host, service) pair, optionally narrowed by a path/component.
    Each pass through the loop increments `cycles`; a pass that yields no new
    intel marks the surface `exhausted`.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    host: str
    service: str = ""               # http, smb, ftp, ldap, mssql, ssh, …
    port: Optional[int] = None
    component: str = ""             # optional narrowing: app path, share name, db
    fingerprint: str = ""          # product/version banner, e.g. "MinIO", "nginx 1.26.3"
    label: str = ""                # display label, e.g. "http://10.0.0.5:8080"
    origin: str = "initial"        # how discovered: initial, lateral, credential, deeper
    status: str = "pending"        # pending, active, exhausted
    cycles: int = 0
    notes: str = ""                # operator/agent context carried into the cycle

    def key(self) -> str:
        return f"{self.host}:{self.port or ''}/{self.service}/{self.component}".lower()


class TestPlanItem(BaseModel):
    action: str                    # what to attempt
    rationale: str = ""            # why — the reasoning trail
    technique: str = ""            # category/label (e.g. "IDOR", "default-creds")
    status: str = "pending"        # pending, attempted, succeeded, failed


class TestPlan(BaseModel):
    """Planner output for one surface — a vetted list the exploit phase works from."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    surface_id: str
    surface_label: str = ""
    items: List[TestPlanItem] = []
    created_by: str = ""
    notes: str = ""
    timestamp: datetime = Field(default_factory=lambda: now_local())


class EngagementBrief(BaseModel):
    """Structured intake parsed from free-form operator input."""
    targets: List[str] = []
    out_of_scope: List[str] = []
    objective: str = ""
    focus_areas: List[str] = []
    tech_context: str = ""                 # free-text background, injected into every agent
    credentials: List[Dict[str, Any]] = []  # {username, secret, service}
    allowed_phases: List[str] = Field(
        default_factory=lambda: ["discovery", "assessment", "reporting"]
    )
    category: str = "pentest"              # pentest | re | code
    entry: str = "pentest/enumeration"
    rationale: str = ""

    @property
    def primary_target(self) -> Optional[str]:
        return self.targets[0] if self.targets else None

    @property
    def exploitation_allowed(self) -> bool:
        return "exploitation" in self.allowed_phases


class Assessment(BaseModel):
    """A full pentest session — one target, one or more agents, one file."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:12])
    target: str
    objective: Optional[str] = None
    start_time: datetime = Field(default_factory=lambda: now_local())
    end_time: Optional[datetime] = None
    status: str = "running"      # running, complete, interrupted
    runs: List[EngagementRun] = []

    def merged_findings(self) -> List[Finding]:
        seen: set = set()
        result: List[Finding] = []
        for run in self.runs:
            for f in run.findings:
                if f.id not in seen:
                    seen.add(f.id)
                    result.append(f)
        return result

    def total_cost(self) -> float:
        return sum(r.estimated_cost_usd for r in self.runs)

    def agents_run(self) -> List[str]:
        return [r.agent for r in self.runs]
