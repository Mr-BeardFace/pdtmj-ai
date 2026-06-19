import os
import shutil
import tempfile

from core import paths

_TMP_VARS = ("TMPDIR", "TEMP", "TMP")


def _save_temp_env():
    return tempfile.tempdir, {k: os.environ.get(k) for k in _TMP_VARS}


def _restore_temp_env(saved):
    tempdir, env = saved
    tempfile.tempdir = tempdir
    for k, v in env.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def test_use_assessment_scratch_redirects_tempfile():
    saved = _save_temp_env()
    aid = "pytest_scratch_abc"
    try:
        d = paths.use_assessment_scratch(aid)
        assert d.exists()
        assert tempfile.tempdir == str(d)
        assert os.environ["TMPDIR"] == str(d)     # subprocess temp redirected too
        # A subsequent tempfile call lands in the per-assessment dir, not /tmp.
        fd, p = tempfile.mkstemp()
        os.close(fd)
        try:
            assert str(d) in p
        finally:
            os.unlink(p)
    finally:
        _restore_temp_env(saved)
        shutil.rmtree(paths.WORK_DIR / f"assessment_{aid}", ignore_errors=True)


def test_session_jar_follows_scratch():
    import tools.http_request as hr
    saved = _save_temp_env()
    aid = "pytest_scratch_sess"
    try:
        d = paths.use_assessment_scratch(aid)
        jar = hr._session_jar("admin")
        assert str(d) in jar           # session cookie jar lands in the scratch dir
    finally:
        _restore_temp_env(saved)
        shutil.rmtree(paths.WORK_DIR / f"assessment_{aid}", ignore_errors=True)
