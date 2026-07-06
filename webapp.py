#!/usr/bin/env python3
"""Minimal stdlib web UI for eml-analyzer.

Serves an upload form; on POST the uploaded ``.eml`` / ``.msg`` is written to a
temp file, analysed with :class:`eml_analyzer.analyzer.EmlAnalyzer`, and the
generated :func:`eml_analyzer.reporting.build_html_report` HTML is returned
inline. No database, no framework: only the Python standard library plus the
analyzer package (which pulls in ``requests`` / ``extract-msg``).

External enrichments (VirusTotal, AbuseIPDB, urlscan, ...) are OFF by default so
the service is fully offline/self-contained. Tick the box on the form (and
provide the matching ``*_API_KEY`` env vars) to enable them.

Bind: ``0.0.0.0:${PORT:-8104}``.
"""

from __future__ import annotations

import cgi
import html
import os
import sys
import tempfile
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from eml_analyzer.analyzer import EmlAnalyzer
from eml_analyzer.config import AnalyzerConfig
from eml_analyzer.reporting import build_html_report

PORT = int(os.getenv("PORT", "8104"))
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(25 * 1024 * 1024)))  # 25 MB

UPLOAD_FORM = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>EML Analyzer</title>
<style>
  body{{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
       background:#0f1419;color:#e6e6e6;margin:0;padding:0;}}
  .wrap{{max-width:640px;margin:8vh auto;padding:0 20px;}}
  h1{{font-size:1.8rem;margin:0 0 4px;}}
  p.sub{{color:#8aa0b2;margin:0 0 28px;}}
  .card{{background:#1a2029;border:1px solid #2a3542;border-radius:14px;padding:26px;}}
  input[type=file]{{display:block;width:100%;margin:10px 0 18px;color:#cfe;}}
  label.chk{{display:flex;align-items:center;gap:8px;color:#b8c6d2;font-size:.92rem;margin-bottom:20px;}}
  button{{background:#2f81f7;color:#fff;border:0;border-radius:8px;padding:11px 22px;
          font-size:1rem;cursor:pointer;}}
  button:hover{{background:#3b8bff;}}
  .err{{background:#3a1d1d;border:1px solid #6b2b2b;color:#ffb4b4;border-radius:8px;
        padding:12px 14px;margin-bottom:18px;white-space:pre-wrap;font-family:monospace;font-size:.85rem;}}
  footer{{color:#5a6b7a;font-size:.8rem;margin-top:26px;text-align:center;}}
  a{{color:#6ba7ff;}}
</style>
</head>
<body>
  <div class="wrap">
    <h1>EML Analyzer</h1>
    <p class="sub">Upload an <code>.eml</code> or <code>.msg</code> email &rarr; get a full HTML analysis report.</p>
    {error}
    <div class="card">
      <form method="POST" action="/analyze" enctype="multipart/form-data">
        <input type="file" name="eml" accept=".eml,.msg,message/rfc822" required />
        <label class="chk">
          <input type="checkbox" name="enrich" value="1" />
          Enable external enrichments (needs API keys; makes outbound calls)
        </label>
        <button type="submit">Analyze</button>
      </form>
    </div>
    <footer>
      Powered by <a href="https://github.com/0xMM0X/eml-analyzer">0xMM0X/eml-analyzer</a>.
      Fork with web UI &mdash; part of Wazuh Full SOC.
    </footer>
  </div>
</body>
</html>
"""


def render_form(error: str | None = None) -> bytes:
    block = f'<div class="err">{html.escape(error)}</div>' if error else ""
    return UPLOAD_FORM.format(error=block).encode("utf-8")


def analyze_bytes(data: bytes, filename: str, enrich: bool) -> str:
    """Write ``data`` to a temp file, run the analyzer, return report HTML."""
    suffix = ".msg" if filename.lower().endswith(".msg") else ".eml"
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        config = AnalyzerConfig.from_env()
        analyzer = EmlAnalyzer(config, verbose=False, debug=False)
        report = analyzer.analyze_path(
            tmp_path,
            enable_enrichments=enrich,
            enable_macro_analysis=True,
            embed_attachments=False,
        )
        output = analyzer.report_as_dict(report)
        theme = "dark" if config.report_dark else "light"
        return build_html_report(
            output,
            theme=theme,
            show_score_details=config.report_score_details,
            defang_urls=config.report_defang_urls,
        )
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


class Handler(BaseHTTPRequestHandler):
    server_version = "eml-analyzer-web/1.0"

    def _send(self, code: int, body: bytes, content_type: str = "text/html; charset=utf-8") -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/", "/index.html"):
            self._send(200, render_form())
        elif self.path in ("/health", "/healthz"):
            self._send(200, b"ok", "text/plain; charset=utf-8")
        else:
            self._send(404, b"not found", "text/plain; charset=utf-8")

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/analyze":
            self._send(404, b"not found", "text/plain; charset=utf-8")
            return
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length > MAX_UPLOAD_BYTES:
            self._send(413, render_form(f"Upload too large (> {MAX_UPLOAD_BYTES} bytes)."))
            return
        try:
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={"REQUEST_METHOD": "POST",
                         "CONTENT_TYPE": self.headers.get("Content-Type", "")},
            )
            field = form["eml"] if "eml" in form else None
            if field is None or not getattr(field, "filename", None):
                self._send(400, render_form("No file uploaded."))
                return
            data = field.file.read()
            if not data:
                self._send(400, render_form("Uploaded file is empty."))
                return
            enrich = "enrich" in form
            report_html = analyze_bytes(data, field.filename, enrich)
            self._send(200, report_html.encode("utf-8"))
        except Exception as exc:  # noqa: BLE001 — surface analyzer errors to user
            sys.stderr.write(traceback.format_exc())
            self._send(500, render_form(f"Analysis failed: {exc}"))

    def log_message(self, fmt: str, *args) -> None:  # quieter default logging
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    sys.stderr.write(f"eml-analyzer web UI listening on 0.0.0.0:{PORT}\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
