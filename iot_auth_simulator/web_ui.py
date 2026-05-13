"""Local web UI for running and inspecting simulator output."""

import argparse
import json
import logging
import mimetypes
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.simulator_runner import SimulationOptions, run_simulation


BASE_DIR = Path(__file__).resolve().parent
GENERATED_DIR = BASE_DIR / "data" / "generated"
logger = logging.getLogger(__name__)


INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>IoT Authentication Simulator</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f6f7fb;
      --panel: #ffffff;
      --ink: #172033;
      --muted: #667085;
      --line: #d9deea;
      --accent: #1976d2;
      --accent-2: #00897b;
      --danger: #d32f2f;
      --warn: #ef8f00;
      --shadow: 0 14px 34px rgba(23, 32, 51, 0.08);
    }

    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--ink);
    }

    header {
      background: #102033;
      color: white;
      padding: 22px 28px;
      border-bottom: 4px solid var(--accent-2);
    }

    header h1 {
      margin: 0;
      font-size: 24px;
      line-height: 1.2;
      letter-spacing: 0;
    }

    header p {
      margin: 6px 0 0;
      color: #cbd5e1;
      max-width: 900px;
      line-height: 1.45;
    }

    main {
      width: min(1280px, calc(100vw - 32px));
      margin: 24px auto 42px;
      display: grid;
      gap: 18px;
    }

    .toolbar, .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
    }

    .toolbar {
      display: grid;
      grid-template-columns: minmax(220px, 1fr) repeat(2, minmax(170px, max-content)) max-content;
      gap: 18px;
      align-items: end;
      padding: 18px;
    }

    label {
      display: grid;
      gap: 8px;
      color: var(--muted);
      font-size: 13px;
      font-weight: 700;
    }

    input[type="number"] {
      width: 100%;
      min-height: 42px;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 9px 11px;
      color: var(--ink);
      font: inherit;
      background: #fff;
    }

    .toggle {
      display: flex;
      align-items: center;
      gap: 10px;
      min-height: 42px;
      color: var(--ink);
      font-size: 14px;
      font-weight: 700;
    }

    .toggle input { width: 18px; height: 18px; }

    button {
      border: 0;
      border-radius: 6px;
      min-height: 42px;
      padding: 0 18px;
      font: inherit;
      font-weight: 800;
      cursor: pointer;
      background: var(--accent);
      color: #fff;
    }

    button:disabled {
      cursor: wait;
      opacity: 0.7;
    }

    .grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(150px, 1fr));
      gap: 14px;
    }

    .metric {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 16px;
      min-height: 106px;
      display: grid;
      align-content: center;
      gap: 7px;
    }

    .metric span {
      color: var(--muted);
      font-size: 13px;
      font-weight: 700;
    }

    .metric strong {
      font-size: 30px;
      line-height: 1;
      letter-spacing: 0;
    }

    .panel {
      overflow: hidden;
    }

    .panel-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding: 16px 18px;
      border-bottom: 1px solid var(--line);
    }

    .panel h2 {
      margin: 0;
      font-size: 17px;
      letter-spacing: 0;
    }

    .status {
      color: var(--muted);
      font-size: 13px;
      font-weight: 700;
    }

    .visuals {
      display: grid;
      grid-template-columns: minmax(280px, 1fr) minmax(280px, 1fr);
      gap: 18px;
      padding: 18px;
    }

    .chart {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
      min-height: 260px;
      background: #fbfcff;
    }

    .chart h3 {
      margin: 0 0 12px;
      font-size: 14px;
    }

    .bars {
      display: grid;
      gap: 12px;
      margin-top: 14px;
    }

    .bar-row {
      display: grid;
      grid-template-columns: 120px 1fr 50px;
      align-items: center;
      gap: 10px;
      font-size: 13px;
      color: var(--muted);
    }

    .bar-track {
      height: 16px;
      background: #e9edf5;
      border-radius: 999px;
      overflow: hidden;
    }

    .bar-fill {
      height: 100%;
      min-width: 4px;
      background: var(--accent);
    }

    .bar-fill.replay { background: var(--danger); }
    .bar-fill.normal { background: var(--accent-2); }
    .bar-fill.warn { background: var(--warn); }

    .downloads {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
    }

    .downloads a {
      display: inline-flex;
      align-items: center;
      min-height: 34px;
      padding: 0 12px;
      border-radius: 6px;
      background: #edf4ff;
      color: #0d47a1;
      text-decoration: none;
      font-size: 13px;
      font-weight: 800;
    }

    .table-wrap {
      overflow: auto;
      max-height: 480px;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      min-width: 980px;
      font-size: 13px;
    }

    th, td {
      padding: 11px 12px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      white-space: nowrap;
    }

    th {
      position: sticky;
      top: 0;
      z-index: 1;
      background: #f8fafc;
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0;
    }

    .pill {
      display: inline-flex;
      align-items: center;
      min-height: 24px;
      padding: 0 8px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 800;
      background: #e8f5e9;
      color: #1b5e20;
    }

    .pill.bad {
      background: #ffebee;
      color: #b71c1c;
    }

    .empty {
      padding: 28px 18px;
      color: var(--muted);
      text-align: center;
    }

    @media (max-width: 900px) {
      .toolbar, .visuals, .grid {
        grid-template-columns: 1fr;
      }

      header { padding: 18px 16px; }
      main { width: min(100vw - 20px, 1280px); margin-top: 14px; }
    }
  </style>
</head>
<body>
  <header>
    <h1>IoT Authentication Flow Simulator</h1>
  </header>

  <main>
    <section class="toolbar" aria-label="Simulation controls">
      <label>
        Devices
        <input id="numDevices" type="number" min="1" max="100" value="5">
      </label>
      <label class="toggle"><input id="includeNormal" type="checkbox" checked> Normal flow</label>
      <label class="toggle"><input id="includeReplay" type="checkbox" checked> Replay attack</label>
      <button id="runBtn" type="button">Run Simulation</button>
    </section>

    <section class="grid" aria-label="Simulation metrics">
      <article class="metric"><span>Devices</span><strong id="metricDevices">0</strong></article>
      <article class="metric"><span>Total Events</span><strong id="metricEvents">0</strong></article>
      <article class="metric"><span>Anomalies</span><strong id="metricAnomalies">0</strong></article>
      <article class="metric"><span>Anomaly Ratio</span><strong id="metricRatio">0%</strong></article>
    </section>

    <section class="panel">
      <div class="panel-head">
        <h2>Run Output</h2>
        <span id="status" class="status">Ready</span>
      </div>
      <div class="visuals">
        <div class="chart">
          <h3>Scenario Volume</h3>
          <div id="scenarioBars" class="bars"></div>
        </div>
        <div class="chart">
          <h3>Lifecycle Phases</h3>
          <div id="phaseBars" class="bars"></div>
        </div>
      </div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <h2>Generated Files</h2>
        <div id="downloads" class="downloads"></div>
      </div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <h2>Recent Events</h2>
        <span class="status">Latest 80 rows</span>
      </div>
      <div id="tableWrap" class="table-wrap">
        <div class="empty">Run the simulator to see event records.</div>
      </div>
    </section>
  </main>

  <script>
    const runBtn = document.getElementById("runBtn");
    const statusEl = document.getElementById("status");

    runBtn.addEventListener("click", runSimulation);

    function setMetric(id, value) {
      document.getElementById(id).textContent = value;
    }

    function renderBars(containerId, rows, className = "") {
      const container = document.getElementById(containerId);
      const max = Math.max(1, ...rows.map((row) => row.value));
      container.innerHTML = rows.length
        ? rows.map((row) => `
          <div class="bar-row">
            <strong>${escapeHtml(row.label)}</strong>
            <div class="bar-track"><div class="bar-fill ${className}" style="width:${Math.max(4, (row.value / max) * 100)}%"></div></div>
            <span>${row.value}</span>
          </div>
        `).join("")
        : '<div class="empty">No events generated.</div>';
    }

    function renderDownloads(files) {
      const downloads = document.getElementById("downloads");
      downloads.innerHTML = Object.entries(files).map(([key, file]) => {
        const label = key.replace("_", " ").toUpperCase();
        return `<a href="${file.url}" download>${label}</a>`;
      }).join("");
    }

    function renderTable(events) {
      const wrap = document.getElementById("tableWrap");
      if (!events.length) {
        wrap.innerHTML = '<div class="empty">No events generated.</div>';
        return;
      }

      const rows = events.slice(-80).reverse();
      wrap.innerHTML = `
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Device</th>
              <th>Phase</th>
              <th>Attack</th>
              <th>Anomaly</th>
              <th>Auth</th>
              <th>Gateway</th>
              <th>Duplicate</th>
              <th>Replay Window</th>
              <th>Trust</th>
            </tr>
          </thead>
          <tbody>
            ${rows.map((event) => `
              <tr>
                <td>${escapeHtml(String(event.timestamp || "").replace("T", " ").slice(0, 19))}</td>
                <td>${escapeHtml(event.device_id)}</td>
                <td>${escapeHtml(event.lifecycle_phase)}</td>
                <td>${escapeHtml(event.attack_type)}</td>
                <td><span class="pill ${event.is_anomaly ? "bad" : ""}">${event.is_anomaly ? "yes" : "no"}</span></td>
                <td>${escapeHtml(event.auth_result)}</td>
                <td>${escapeHtml(event.gateway_decision)}</td>
                <td>${event.duplicate_flag ? "yes" : "no"}</td>
                <td>${event.replay_window_violation ? "yes" : "no"}</td>
                <td>${Number(event.trust_score || 0).toFixed(2)}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      `;
    }

    async function runSimulation() {
      runBtn.disabled = true;
      statusEl.textContent = "Running...";

      try {
        const response = await fetch("/api/run", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            num_devices: Number(document.getElementById("numDevices").value),
            include_normal: document.getElementById("includeNormal").checked,
            include_replay: document.getElementById("includeReplay").checked,
          }),
        });

        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || "Simulation failed");

        setMetric("metricDevices", payload.summary.devices);
        setMetric("metricEvents", payload.summary.total_events);
        setMetric("metricAnomalies", payload.summary.anomalies);
        setMetric("metricRatio", `${payload.summary.anomaly_ratio}%`);

        renderBars("scenarioBars", [
          { label: "Normal", value: payload.summary.normal_events },
          { label: "Replay", value: payload.summary.replay_events },
        ], "normal");
        renderBars("phaseBars", payload.lifecycle_counts, "warn");
        renderDownloads(payload.files);
        renderTable(payload.events);
        statusEl.textContent = `Completed in ${payload.summary.duration_ms} ms`;
      } catch (error) {
        statusEl.textContent = error.message;
      } finally {
        runBtn.disabled = false;
      }
    }

    function escapeHtml(value) {
      return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
    }
  </script>
</body>
</html>
"""


class SimulatorUIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the simulator UI."""

    def do_GET(self) -> None:
        if self.path == "/" or self.path == "/index.html":
            self.send_text(INDEX_HTML, "text/html; charset=utf-8")
            return

        if self.path.startswith("/generated/"):
            self.serve_generated_file()
            return

        self.send_error(404, "Not found")

    def do_POST(self) -> None:
        if self.path != "/api/run":
            self.send_error(404, "Not found")
            return

        try:
            body = self.rfile.read(int(self.headers.get("Content-Length", "0") or 0))
            data = json.loads(body.decode("utf-8") or "{}")
            payload = run_from_request(data)
            self.send_json(payload)
        except Exception as exc:
            logger.exception("Simulation failed")
            self.send_json({"error": str(exc)}, status=500)

    def serve_generated_file(self) -> None:
        relative_name = unquote(self.path.removeprefix("/generated/"))
        file_path = (GENERATED_DIR / relative_name).resolve()
        generated_root = GENERATED_DIR.resolve()

        if generated_root not in file_path.parents or not file_path.is_file():
            self.send_error(404, "Not found")
            return

        content_type = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(file_path.stat().st_size))
        self.send_header("Content-Disposition", f'attachment; filename="{file_path.name}"')
        self.end_headers()
        self.wfile.write(file_path.read_bytes())

    def send_text(self, text: str, content_type: str, status: int = 200) -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, payload: dict, status: int = 200) -> None:
        self.send_text(json.dumps(payload), "application/json; charset=utf-8", status)

    def log_message(self, format: str, *args) -> None:
        logger.info("%s - %s", self.address_string(), format % args)


def run_from_request(data: dict) -> dict:
    """Run the simulator from a JSON request body."""
    import time

    num_devices = int(data.get("num_devices", 5))
    include_normal = bool(data.get("include_normal", True))
    include_replay = bool(data.get("include_replay", True))

    if num_devices < 1 or num_devices > 100:
        raise ValueError("Device count must be between 1 and 100.")
    if not include_normal and not include_replay:
        raise ValueError("Select at least one scenario.")

    started = time.perf_counter()
    result = run_simulation(
        SimulationOptions(
            num_devices=num_devices,
            include_normal=include_normal,
            include_replay=include_replay,
            export_dir=GENERATED_DIR,
        )
    )
    duration_ms = round((time.perf_counter() - started) * 1000)

    lifecycle_counts: dict[str, int] = {}
    for event in result.all_events:
        lifecycle_counts[event.lifecycle_phase or "UNKNOWN"] = (
            lifecycle_counts.get(event.lifecycle_phase or "UNKNOWN", 0) + 1
        )

    total_events = len(result.all_events)
    anomaly_ratio = round((result.anomaly_count / total_events) * 100, 1) if total_events else 0

    return {
        "summary": {
            "devices": len(result.devices),
            "normal_events": len(result.normal_events),
            "replay_events": len(result.replay_events),
            "total_events": total_events,
            "anomalies": result.anomaly_count,
            "anomaly_ratio": anomaly_ratio,
            "duration_ms": duration_ms,
        },
        "lifecycle_counts": [
            {"label": key, "value": value}
            for key, value in sorted(lifecycle_counts.items(), key=lambda item: item[0])
        ],
        "files": {
            key: {"name": path.name, "url": f"/generated/{path.name}"}
            for key, path in result.exported_files.items()
        },
        "events": [event.to_dict() for event in result.all_events],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the simulator web UI.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    server = ThreadingHTTPServer((args.host, args.port), SimulatorUIHandler)
    print(f"Simulator UI running at http://{args.host}:{args.port}")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
