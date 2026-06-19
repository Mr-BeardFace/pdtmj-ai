"""captcha_solve — local OCR of simple image captchas. tesseract/PIL are mocked
so the test runs without the OCR deps installed."""
import base64
import sys
import types

import tools.captcha_solve as cs


def _install_fakes(monkeypatch, ocr_return="12345"):
    pt = types.ModuleType("pytesseract")
    pt.image_to_string = lambda img, config="": ocr_return
    monkeypatch.setitem(sys.modules, "pytesseract", pt)

    class _Img:
        size = (50, 20)
        def convert(self, _m): return self
        def resize(self, s, _r): self.size = s; return self
        def filter(self, _f): return self
        def point(self, _fn): return self

    Image = types.ModuleType("PIL.Image")
    Image.open = lambda _b: _Img()
    Image.LANCZOS = 1
    ImageFilter = types.ModuleType("PIL.ImageFilter")
    ImageFilter.MedianFilter = lambda n: n
    ImageOps = types.ModuleType("PIL.ImageOps")
    ImageOps.autocontrast = lambda img: img
    PIL = types.ModuleType("PIL")
    PIL.Image, PIL.ImageFilter, PIL.ImageOps = Image, ImageFilter, ImageOps
    for name, mod in (("PIL", PIL), ("PIL.Image", Image),
                      ("PIL.ImageFilter", ImageFilter), ("PIL.ImageOps", ImageOps)):
        monkeypatch.setitem(sys.modules, name, mod)


def test_errors_without_tesseract(monkeypatch):
    monkeypatch.setattr(cs.shutil, "which", lambda _n: None)
    out = cs.captcha_solve(image_b64="x")
    assert "error" in out and "tesseract" in out["error"].lower()


def test_requires_an_image_source(monkeypatch):
    monkeypatch.setattr(cs.shutil, "which", lambda _n: "/usr/bin/tesseract")
    _install_fakes(monkeypatch)
    assert "error" in cs.captcha_solve()                      # nothing to read


def test_solves_and_strips_whitespace(monkeypatch):
    monkeypatch.setattr(cs.shutil, "which", lambda _n: "/usr/bin/tesseract")
    _install_fakes(monkeypatch, ocr_return="12 34\n5\n")
    out = cs.captcha_solve(image_b64=base64.b64encode(b"img").decode(), charset="digits")
    assert out["solved"] == "12345"
    assert out["length"] == 5
    assert out["charset"] == "digits"


def test_named_charset_maps_to_whitelist(monkeypatch):
    monkeypatch.setattr(cs.shutil, "which", lambda _n: "/usr/bin/tesseract")
    captured = {}
    _install_fakes(monkeypatch)
    sys.modules["pytesseract"].image_to_string = \
        lambda img, config="": captured.update(config=config) or "9"
    cs.captcha_solve(image_b64=base64.b64encode(b"img").decode(), charset="digits", psm=8)
    assert "0123456789" in captured["config"] and "--psm 8" in captured["config"]


def test_registered_and_in_web_scope():
    from core.registry import build_registry, load_all_agents
    reg = build_registry()
    names = {t.name for t in reg.get_by_scope(load_all_agents()["pentest/web"].scope)}
    assert "captcha_solve" in names
