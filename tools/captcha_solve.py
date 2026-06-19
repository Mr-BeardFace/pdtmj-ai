"""Solve a simple image CAPTCHA via local OCR (tesseract + Pillow).

For authorized engagements where a registration/login step is gated by a basic
image CAPTCHA — distorted digits/letters, e.g. Gogs' default dchest/captcha. It
fetches the captcha image (in the SAME `http_request` session as the form, so the
server-side captcha id matches the cookies), preprocesses it for OCR, and reads
it with tesseract restricted to the expected charset.

Scope: this is image-text OCR only. Behavioral / JS challenges (reCAPTCHA,
hCaptcha, Cloudflare Turnstile) are NOT image-OCR solvable — for those, pivot to
another vector. OCR is best-effort: if the form rejects a solve, re-fetch a fresh
captcha and try again (the value/id rotate per request).
"""
from __future__ import annotations

import base64
import io
import os
import re
import shutil
import tempfile

_SAFE_NAME = re.compile(r"[^A-Za-z0-9_.-]")

# Named charsets → tesseract whitelist. A literal custom string is also accepted.
_CHARSETS = {
    "digits": "0123456789",
    "lower":  "abcdefghijklmnopqrstuvwxyz",
    "upper":  "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "alnum":  "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
}


def _session_cookies(session: str):
    """Load cookies from the http_request session jar so the captcha image is
    fetched within the same session as the form (the captcha id is tied to it)."""
    import http.cookiejar
    path = os.path.join(tempfile.gettempdir(), "pentest_sessions",
                        _SAFE_NAME.sub("_", session) + ".jar")
    jar = http.cookiejar.MozillaCookieJar(path)
    try:
        jar.load(ignore_discard=True, ignore_expires=True)
    except Exception:
        return None
    return jar


def _fetch_image(url: str, session: str, timeout: int):
    import httpx
    cookies = _session_cookies(session) if session else None
    try:
        resp = httpx.get(url, cookies=cookies, timeout=timeout,
                         verify=False, follow_redirects=True)
    except Exception as e:  # noqa: BLE001
        return None, f"failed to fetch captcha image: {e}"
    if resp.status_code != 200:
        return None, f"captcha image fetch returned HTTP {resp.status_code}"
    return resp.content, None


def _preprocess(img):
    """Grayscale → upscale → autocontrast → denoise → binarize, to give tesseract
    a clean high-contrast target (small distorted captchas OCR poorly raw)."""
    from PIL import Image, ImageFilter, ImageOps
    img = img.convert("L")
    w, h = img.size
    if w < 300:                                  # upscale small captchas
        scale = max(2, 300 // max(w, 1))
        img = img.resize((w * scale, h * scale), Image.LANCZOS)
    img = ImageOps.autocontrast(img)
    img = img.filter(ImageFilter.MedianFilter(3))
    return img.point(lambda p: 255 if p > 140 else 0)   # binarize


def captcha_solve(image_url: str = "", image_b64: str = "", image_path: str = "",
                  charset: str = "digits", session: str = "",
                  psm: int = 7, timeout: int = 20) -> dict:
    if not shutil.which("tesseract"):
        return {"error": "tesseract not found in PATH — install with "
                         "`apt_install tesseract-ocr` (or apt-get install -y tesseract-ocr)"}
    try:
        import pytesseract
        from PIL import Image
    except Exception as e:  # noqa: BLE001
        return {"error": f"OCR libraries missing ({e}) — `pip_install pytesseract Pillow`"}

    # ── obtain image bytes ──────────────────────────────────────────────────────
    if image_url:
        data, err = _fetch_image(image_url, session, timeout)
        if err:
            return {"error": err, "image_url": image_url}
    elif image_b64:
        try:
            data = base64.b64decode(image_b64)
        except Exception as e:  # noqa: BLE001
            return {"error": f"invalid base64: {e}"}
    elif image_path:
        try:
            with open(image_path, "rb") as f:
                data = f.read()
        except Exception as e:  # noqa: BLE001
            return {"error": f"cannot read image_path: {e}"}
    else:
        return {"error": "provide image_url, image_b64, or image_path"}

    try:
        img = Image.open(io.BytesIO(data))
    except Exception as e:  # noqa: BLE001
        return {"error": f"not a readable image: {e}"}

    whitelist = _CHARSETS.get(charset, charset)        # named set, else literal charset
    config = f"--psm {int(psm)} -c tessedit_char_whitelist={whitelist}"
    try:
        raw = pytesseract.image_to_string(_preprocess(img), config=config)
    except Exception as e:  # noqa: BLE001
        return {"error": f"OCR failed: {e}"}
    text = re.sub(r"\s+", "", raw)

    return {
        "solved":    text,
        "length":    len(text),
        "charset":   charset,
        "image_url": image_url or None,
        "note": ("Best-effort OCR. Submit it in the SAME session you fetched it in. "
                 "If the form rejects it, re-fetch a fresh captcha and solve again — "
                 "the value and id rotate each request."),
        "_command": f"tesseract <captcha> --psm {psm} (whitelist={charset})",
    }


TOOL_DEFINITION = {
    "name": "captcha_solve",
    "description": (
        "Solve a simple IMAGE captcha (distorted digits/letters, e.g. Gogs' default) with local "
        "tesseract OCR, so a registration/login step gated by one can proceed. Fetch the captcha "
        "image by URL (pass the same `session` name you use with http_request, so the captcha id "
        "matches your cookies), or hand it `image_b64`/`image_path` directly. Set `charset` to the "
        "expected character class ('digits' for Gogs, 'alnum', 'lower', 'upper', or a literal "
        "whitelist string). Returns the decoded text in `solved`. NOT for behavioral/JS challenges "
        "(reCAPTCHA, hCaptcha, Turnstile) — those aren't OCR-solvable; pivot to another vector. "
        "Best-effort: if rejected, re-fetch a fresh captcha and retry."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "image_url": {"type": "string",
                          "description": "URL of the captcha image (fetched with the session cookies if `session` is set)."},
            "image_b64": {"type": "string",
                          "description": "Base64 of the captcha image, if you already have the bytes."},
            "image_path": {"type": "string",
                           "description": "Local path to a saved captcha image."},
            "charset": {"type": "string",
                        "description": "Expected characters: 'digits' (default), 'alnum', 'lower', 'upper', or a literal whitelist like '0123456789'."},
            "session": {"type": "string",
                        "description": "http_request session name to share cookies with, so the fetched captcha matches the form's session."},
            "psm": {"type": "integer",
                    "description": "tesseract page-segmentation mode (default 7 = single text line; try 8 = single word, or 6)."},
            "timeout": {"type": "integer", "description": "Image-fetch timeout in seconds (default 20)."},
        },
        "required": [],
    },
}
