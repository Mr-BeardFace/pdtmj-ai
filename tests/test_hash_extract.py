"""hash_extract wraps the *2john helpers: infer the format, run the extractor,
strip the filename prefix to the bare hash, and report a hashcat mode."""
from tools import hash_extract as he


def test_infer_format_by_extension():
    assert he._infer_format("/x/secret.zip") == "zip"
    assert he._infer_format("/x/db.kdbx") == "keepass"
    assert he._infer_format("/home/u/id_rsa") == "ssh"
    assert he._infer_format("/x/report.pdf") == "pdf"


def test_strip_to_hash_drops_filename_prefix():
    out = "secret.zip:$zip2$*0*1*0*deadbeef*$/zip2$\n"
    h = he._strip_to_hash(out)
    assert h.startswith("$zip2$") and "secret.zip" not in h


def test_extract_reports_hash_and_mode(tmp_path, monkeypatch):
    f = tmp_path / "secret.zip"
    f.write_bytes(b"PK\x03\x04")
    monkeypatch.setattr(he, "_find_extractor", lambda n: ["zip2john"])

    class _P:
        stdout = f"{f}:$zip2$*0*1*0*deadbeef*$/zip2$"
        stderr = ""

    monkeypatch.setattr(he.runner, "run", lambda *a, **k: _P())
    r = he.hash_extract(str(f))
    assert r["format"] == "zip" and r["hashcat_mode"] == 13600
    assert r["hash"].startswith("$zip2$") and str(f) not in r["hash"]


def test_unknown_format_errors(tmp_path):
    f = tmp_path / "thing.bin"
    f.write_bytes(b"x")
    assert "error" in he.hash_extract(str(f))


def test_missing_extractor_errors(tmp_path, monkeypatch):
    f = tmp_path / "secret.zip"
    f.write_bytes(b"PK")
    monkeypatch.setattr(he, "_find_extractor", lambda n: None)
    r = he.hash_extract(str(f))
    assert "error" in r and "install John" in r["error"]


def test_missing_file_errors():
    assert "error" in he.hash_extract("/no/such/file.zip")
