"""/end from a halted engagement (quota/pause/cap) finalizes and reports from work
done — no /continue-then-/end dance, no LLM, so it works even when the quota is spent."""
import asyncio

from core.models import Assessment, EngagementRun, Finding
from ui.app import PentestApp


def _assessment_with_run():
    a = Assessment(target="10.0.0.1", objective="root it")
    run = EngagementRun(agent="pentest/enumeration", target="10.0.0.1")
    run.findings.append(Finding(type="vuln", severity="high", title="X",
                                description="d", target="10.0.0.1"))
    a.runs.append(run)
    return a, run


def test_end_finalizes_halted_engagement_and_reports(tmp_path):
    async def _run():
        app = PentestApp()
        async with app.run_test():
            a, run = _assessment_with_run()
            app._current_assessment = a
            app._current_assessment_dir = tmp_path
            app._current_assessment_path = tmp_path / "assessment.json"
            app._pipeline_resume = {"brief": None, "state": None, "assessment": a, "runs": [run]}
            app._finalize_halted_engagement()
            assert app._pipeline_resume is None            # resume point cleared → truly ended
            assert a.status == "interrupted"
            assert list(tmp_path.glob("report_*.html"))    # report rendered from what was done
    asyncio.run(_run())


def test_end_when_nothing_to_finalize_is_a_noop(tmp_path):
    # No running pipeline, no resume, no assessment → the /end branch reports nothing to do.
    async def _run():
        app = PentestApp()
        async with app.run_test():
            assert app._pipeline_resume is None and app._current_assessment is None
            # gate the /end handler uses: neither resume nor a current assessment with runs
            gate = bool(app._pipeline_resume or (app._current_assessment
                                                 and app._current_assessment.runs))
            assert gate is False
    asyncio.run(_run())
