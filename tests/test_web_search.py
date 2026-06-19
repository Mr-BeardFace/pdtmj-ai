"""web_search / fetch_url tools + the orchestrator's OPSEC scrub."""
import types

import tools.web_search as ws
import tools.fetch_url as fu
from core.engagement_state import EngagementState
from core.orchestrator import Orchestrator
from core.tool_registry import ToolRegistry

_DDG_HTML = """
<div class="result">
  <a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fwingftp-cve&rut=z">Wing FTP CVE-2025-47812 writeup</a>
  <a class="result__snippet" href="x">NULL-byte Lua injection in the login handler yields RCE.</a>
</div>
<div class="result">
  <a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexploit-db.com%2F52347">EDB-52347</a>
  <a class="result__snippet" href="x">Proof of concept exploit.</a>
</div>
"""


# ── web_search ────────────────────────────────────────────────────────────────

def test_web_search_parses_ddg(monkeypatch):
    monkeypatch.setattr(ws.httpx, "post", lambda *a, **k: types.SimpleNamespace(text=_DDG_HTML))
    out = ws.web_search("Wing FTP 7.4.3 CVE-2025-47812")
    assert out["count"] == 2
    assert out["results"][0]["url"] == "https://example.com/wingftp-cve"   # uddg decoded
    assert "writeup" in out["results"][0]["title"]
    assert "RCE" in out["results"][0]["snippet"]


def test_web_search_in_tool_guard_blocks_ip_and_internal():
    assert "error" in ws.web_search("exploit 10.129.29.26 smb")
    assert "error" in ws.web_search("default creds for wingdata.htb")


# ── fetch_url (guards run before any network call) ────────────────────────────

def test_fetch_url_rejects_private_internal_and_scheme():
    assert "error" in fu.fetch_url("http://10.0.0.5/admin")        # RFC1918
    assert "error" in fu.fetch_url("http://localhost/x")
    assert "error" in fu.fetch_url("https://dc01.htb/")            # internal TLD
    assert "error" in fu.fetch_url("ftp://example.com/x")          # scheme


def test_fetch_url_html_to_text_strips_markup():
    txt = fu._html_to_text("<html><head><style>x{}</style></head>"
                           "<body><p>Step one.</p><script>bad()</script><p>Step two.</p></body>")
    assert "Step one." in txt and "Step two." in txt
    assert "bad()" not in txt and "x{}" not in txt


# ── orchestrator OPSEC scrub (context-aware) ──────────────────────────────────

def _orch(tmp_path, state):
    return Orchestrator(object(), ToolRegistry(), tmp_path, quiet=True, engagement_state=state)


def _state():
    s = EngagementState(target="10.129.29.26")
    s.recon.host_names["10.129.29.26"] = "wingdata.htb"
    s.add_credential(secret="Welcome2026@", username="wallace.everette", verified=True)
    return s


def _force_web_on(monkeypatch):
    """These tests exercise the OPSEC scrub, not the on/off toggle — force the
    flag on regardless of the repo's config.yaml value."""
    import core.config as _cfg
    _real = _cfg.get
    monkeypatch.setattr(_cfg, "get",
                        lambda k, d=None: True if k == "allow_web_search" else _real(k, d))


def test_scrub_allows_clean_tech_query(tmp_path, monkeypatch):
    _force_web_on(monkeypatch)
    o = _orch(tmp_path, _state())
    assert o._web_research_block({"query": "Wing FTP 7.4.3 CVE exploit steps"}) is None


def test_scrub_blocks_target_and_creds(tmp_path, monkeypatch):
    _force_web_on(monkeypatch)
    o = _orch(tmp_path, _state())
    assert o._web_research_block({"query": "scan 10.129.29.26"})            # IP
    assert o._web_research_block({"query": "wingdata.htb login"})           # target host / internal TLD
    assert o._web_research_block({"query": "is Welcome2026@ reused"})       # secret value
    assert o._web_research_block({"query": "wallace.everette spray"})       # discovered username
    # a generic username is NOT treated as a leak
    assert o._web_research_block({"query": "tomcat default admin password"}) is None


def test_scrub_blocks_when_disabled(tmp_path, monkeypatch):
    import core.config as cfg
    monkeypatch.setattr(cfg, "get", lambda k, d=None: False if k == "allow_web_search" else d)
    o = _orch(tmp_path, _state())
    assert o._web_research_block({"query": "anything generic"})             # disabled → blocked


# ── registry wiring ───────────────────────────────────────────────────────────

def test_tools_registered_and_in_research_agent_scope():
    from core.registry import build_registry, load_all_agents
    reg = build_registry()
    agents = load_all_agents()
    enum = {t.name for t in reg.get_by_scope(agents["pentest/enumeration"].scope)}
    exploit = {t.name for t in reg.get_by_scope(agents["pentest/exploitation"].scope)}
    # Enumeration keeps web_search (flag a CVE lead) but NOT fetch_url — pulling
    # full PoC pages is deep research that belongs to the exploitation phases.
    assert "web_search" in enum
    assert "fetch_url" not in enum
    assert "fetch_url" in exploit
