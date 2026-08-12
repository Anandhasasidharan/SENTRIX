from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

try:
    from fastapi import FastAPI, Query, Request
    from fastapi.responses import HTMLResponse, JSONResponse
    from fastapi.staticfiles import StaticFiles
    from fastapi.templating import Jinja2Templates
    _has_fastapi = True
except ImportError:
    _has_fastapi = False

from sentrix import Sentrix
from sentrix.harness.agentdojo import AGENTDOJO_TASKS, AgentDojoEvaluator
from sentrix.harness.agentdyn import AgentDynEvaluator
from sentrix.harness.dual_benchmark import DualBenchmarkEvaluator
from sentrix.harness.obfuscator import STANDARD_ATTACKS
from sentrix.harness.evaluator import Evaluator
from sentrix.models.policy import AgentPolicy, DataSensitivity


class DashboardApp:
    def __init__(self, sentrix: Sentrix | None = None):
        if not _has_fastapi:
            raise RuntimeError(
                "FastAPI is required for the dashboard. "
                "Install it: pip install fastapi uvicorn jinja2"
            )
        self._sentrix = sentrix or Sentrix()
        self._evaluator = Evaluator(
            reference_monitor=self._sentrix.monitor,
            classifier=self._sentrix.classifier,
        )
        self._configured = False
        self._app = FastAPI(title="Sentrix Dashboard")
        self._setup_routes()

    def _get_templates(self) -> Jinja2Templates:
        here = Path(__file__).parent
        templates_dir = here / "templates"
        return Jinja2Templates(directory=str(templates_dir))

    @property
    def app(self) -> FastAPI:
        return self._app

    def _sentrix_or_fallback(self) -> Sentrix:
        return self._sentrix

    def _setup_routes(self):
        app = self._app

        @app.get("/", response_class=HTMLResponse)
        async def index(request: Request):
            templates = self._get_templates()
            sentrix = self._sentrix_or_fallback()
            summary = sentrix.get_eval_summary()
            timeline_text = sentrix.timeline.render_text_timeline("demo")
            return templates.TemplateResponse(
                "index.html",
                {
                    "request": request,
                    "session_id": "(stateless)",
                    "agent_id": sentrix.agent_id or "(none)",
                    "event_count": sentrix.timeline.get_event_count(),
                    "summary": summary,
                    "timeline": timeline_text,
                },
            )

        @app.get("/timeline", response_class=HTMLResponse)
        async def timeline(
            request: Request,
            session_id: str = Query(default=""),
        ):
            templates = self._get_templates()
            sentrix = self._sentrix_or_fallback()
            sid = session_id or "demo"
            text = sentrix.timeline.render_text_timeline(sid, max_events=200)
            events = sentrix.timeline.get_events(session_id=sid)
            return templates.TemplateResponse(
                "timeline.html",
                {
                    "request": request,
                    "session_id": sid,
                    "timeline_text": text,
                    "events_json": json.dumps([
                        {
                            "id": e.id,
                            "agent": e.agent_id,
                            "role": e.source_role.value if e.source_role else "",
                            "provenance": e.provenance.value,
                            "verdict": e.verdict.value if e.verdict else "",
                            "tool": e.tool_call.tool_name if e.tool_call else "",
                            "blocked_by": e.blocked_by.value if e.blocked_by else "",
                            "score": e.classifier_score,
                        }
                        for e in events
                    ]),
                    "total": len(events),
                },
            )

        @app.get("/dag", response_class=HTMLResponse)
        async def dag(
            request: Request,
            session_id: str = Query(default=""),
        ):
            templates = self._get_templates()
            sentrix = self._sentrix_or_fallback()
            sid = session_id or "demo"
            summary = sentrix._dag_builder.summary(sid, sentrix.timeline)
            return templates.TemplateResponse(
                "dag.html",
                {
                    "request": request,
                    "session_id": sid,
                    "dag_text": summary.get("dag", "(empty)"),
                    "summary_json": json.dumps(summary),
                },
            )

        @app.get("/eval", response_class=HTMLResponse)
        async def eval_page(request: Request):
            templates = self._get_templates()
            sentrix = self._sentrix_or_fallback()
            standard_results = self._evaluator.run_standard(
                attacks=STANDARD_ATTACKS
            )
            obfuscated_results = self._evaluator.run_obfuscated(
                attacks=STANDARD_ATTACKS,
                techniques=["base64", "braille"],
            )
            comparison = self._evaluator.compare_block_rates()
            by_domain = self._evaluator.summary_by_domain()
            return templates.TemplateResponse(
                "eval.html",
                {
                    "request": request,
                    "comparison_json": json.dumps(comparison),
                    "by_domain": [
                        {
                            "domain": s.domain,
                            "total": s.total_attacks,
                            "blocked": s.blocked,
                            "block_rate": f"{s.block_rate:.0%}",
                        }
                        for s in by_domain
                    ],
                    "standard_results": [
                        {
                            "name": r.attack_name,
                            "domain": r.domain,
                            "blocked": r.monitor_blocked or r.classifier_triggered,
                            "detail": r.details,
                        }
                        for r in standard_results
                    ],
                    "obfuscated_results": [
                        {
                            "name": r.attack_name,
                            "domain": r.domain,
                            "tech": r.obfuscation_technique or "",
                            "blocked": r.monitor_blocked or r.classifier_triggered,
                            "detail": r.details,
                        }
                        for r in obfuscated_results
                    ],
                },
            )

        @app.get("/plan", response_class=HTMLResponse)
        async def plan_page(request: Request):
            templates = self._get_templates()
            sentrix = self._sentrix_or_fallback()
            plan_result = None
            plan_json = request.query_params.get("plan", "")
            if plan_json:
                try:
                    plan_result = sentrix.execute_plan(plan_json)
                except Exception as e:
                    plan_result = {"error": str(e)}
            return templates.TemplateResponse(
                "plan.html",
                {
                    "request": request,
                    "plan_result": plan_result,
                    "plan_json": plan_json,
                },
            )

        @app.get("/agentdojo", response_class=HTMLResponse)
        async def agentdojo_page(request: Request):
            templates = self._get_templates()
            sentrix = self._sentrix_or_fallback()
            evaluator = AgentDojoEvaluator(
                reference_monitor=sentrix.monitor,
                classifier=sentrix.classifier,
            )
            report = evaluator.evaluate()
            return templates.TemplateResponse(
                "agentdojo.html",
                {
                    "request": request,
                    "report": report,
                    "tasks": AGENTDOJO_TASKS,
                },
            )

        @app.get("/dualbenchmark", response_class=HTMLResponse)
        async def dualbenchmark_page(request: Request):
            templates = self._get_templates()
            sentrix = self._sentrix_or_fallback()
            evaluator = DualBenchmarkEvaluator(
                reference_monitor=sentrix.monitor,
                classifier=sentrix.classifier,
            )
            report = evaluator.evaluate()
            return templates.TemplateResponse(
                "dualbenchmark.html",
                {
                    "request": request,
                    "report": report,
                },
            )

        @app.get("/report", response_class=HTMLResponse)
        async def report(
            request: Request,
            session_id: str = Query(default=""),
        ):
            templates = self._get_templates()
            sentrix = self._sentrix_or_fallback()
            sid = session_id or "demo"
            try:
                taint_results = sentrix.scan_tool_code(".")
                report_obj = sentrix.generate_report(sid, taint_results=taint_results)
                markdown = sentrix._reporter.render_markdown(report_obj, taint_results=taint_results)
            except Exception as e:
                markdown = f"Error generating report: {e}"
            return templates.TemplateResponse(
                "report.html",
                {
                    "request": request,
                    "session_id": sid,
                    "markdown": markdown,
                },
            )

        @app.get("/health")
        async def health():
            return {"status": "ok", "version": "0.1.0"}

    def run(self, host: str = "0.0.0.0", port: int = 8400):
        import uvicorn
        logger.info(
            "Sentrix Dashboard starting at http://%s:%d",
            host, port,
        )
        uvicorn.run(self._app, host=host, port=port, log_level="info")


def main():
    logging.basicConfig(level=logging.INFO)
    dash = DashboardApp()
    dash.run()


if __name__ == "__main__":
    main()
