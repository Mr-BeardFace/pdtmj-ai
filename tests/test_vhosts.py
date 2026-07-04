"""Multiple vhosts per IP:port. Hostname = the machine's DNS/LDAP identity (one per
IP); vhost = a website (HTTP Host header) served on the IP:port — each its own service
entry, auto-scoped, never overwriting the machine identity."""
from core.engagement_state import EngagementState


def _scoped(target="10.0.0.1"):
    s = EngagementState(target=target)
    s.add_scope(target)
    return s


def test_hostname_identity_and_vhosts_are_separate():
    s = _scoped()
    s.annotate_service(host="10.0.0.1", port=80, service="http", app="nginx",
                       hostname="DC01.corp.htb")
    s.annotate_service(host="10.0.0.1", port=80, service="http", app="nginx PHP",
                       vhost="store.corp.htb")
    s.annotate_service(host="10.0.0.1", port=80, service="http", app="Werkzeug",
                       vhost="dev.corp.htb")
    # one machine identity in the Hostname slot
    assert s.recon.host_names["10.0.0.1"] == "dc01.corp.htb"
    # website names never land in host_names
    assert "store.corp.htb" not in s.recon.host_names.values()
    # three distinct service rows: baseline (no vhost) + two vhosts
    assert sorted(sv.get("vhost", "") for sv in s.services if sv["port"] == 80) == \
        ["", "dev.corp.htb", "store.corp.htb"]
    # each vhost keeps its own app
    assert next(sv for sv in s.services if sv.get("vhost") == "dev.corp.htb")["app"] == "Werkzeug"


def test_vhosts_auto_scoped():
    s = _scoped()
    s.annotate_service(host="10.0.0.1", port=443, vhost="admin.corp.htb")
    assert s.in_scope("admin.corp.htb")


def test_same_vhost_upserts_not_duplicates():
    s = _scoped()
    s.annotate_service(host="10.0.0.1", port=80, service="http", vhost="store.corp.htb")
    s.annotate_service(host="10.0.0.1", port=80, app="Rails", vhost="store.corp.htb")
    rows = [sv for sv in s.services if sv.get("vhost") == "store.corp.htb"]
    assert len(rows) == 1 and rows[0]["app"] == "Rails" and rows[0]["service"] == "http"


def test_web_vhost_does_not_scope_when_ip_out_of_scope():
    s = EngagementState(target="10.0.0.1")          # nothing added to scope
    s.annotate_service(host="10.9.9.9", port=80, vhost="evil.example.com")
    assert not s.in_scope("evil.example.com")


def test_vhost_display_hides_baseline_groups_and_copies_full():
    # Option #4: a real vhost hides the bare :80 baseline row; sibling vhosts blank the
    # shared IP/Hostname (grouped look) but copy still yields the full line.
    import asyncio
    from ui.app import PentestApp
    from textual.widgets import DataTable

    async def _run():
        app = PentestApp()
        async with app.run_test() as pilot:
            app._add_host_row("10.0.0.1", {"port": 80, "protocol": "tcp",
                                           "service": "http", "version": "nginx"})
            app._host_name["10.0.0.1"] = "dc01.corp.htb"
            for vh, fp in (("store.corp.htb", "nginx/PHP"), ("dev.corp.htb", "Werkzeug")):
                app._add_host_row("10.0.0.1", {"port": 80, "protocol": "tcp", "service": "http",
                                               "version": fp, "vhost": vh}, authoritative=True)
            app._add_host_row("10.0.0.1", {"port": 445, "protocol": "tcp", "service": "smb"})
            await pilot.pause()
            dt = app.query_one("#hosts-table", DataTable)
            keys = [str(r.key.value) for r in dt.ordered_rows]
            assert "10.0.0.1:80/tcp:" not in keys                      # baseline hidden
            assert "10.0.0.1:80/tcp:store.corp.htb" in keys
            assert "10.0.0.1:80/tcp:dev.corp.htb" in keys
            assert "10.0.0.1:445/tcp:" in keys                         # non-web baseline stays

            web = [(str(r.key.value), dt.get_row(r.key)) for r in dt.ordered_rows
                   if r.key.value.startswith("10.0.0.1:80/tcp:")]
            assert web[0][1][0] == "10.0.0.1"                          # leader shows IP
            assert web[1][1][0] == ""                                  # sibling blanked
            assert web[0][1][2] == "dev.corp.htb"                      # alpha order, dev first
            data = app._host_rowdata[web[1][0]]                        # blanked sibling
            assert data[0] == "10.0.0.1" and data[1] == "dc01.corp.htb"   # copy stays full

    asyncio.run(_run())


def test_host_sort_key_orders_vhosts_within_ip_port():
    from ui.app import PentestApp
    k = PentestApp._host_sort_key
    rows = [("10.0.0.1", "TCP", "80", "store.htb"),
            ("10.0.0.1", "TCP", "80", ""),
            ("10.0.0.1", "TCP", "80", "admin.htb"),
            ("10.0.0.1", "TCP", "445", "")]
    ordered = [r[3] or "(base)" for r in sorted(rows, key=k)]
    # port 80 group before 445; within 80, baseline "" sorts first then alpha vhosts
    assert ordered == ["(base)", "admin.htb", "store.htb", "(base)"]
