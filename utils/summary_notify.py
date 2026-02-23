#!/usr/bin/env python3
"""
Unified summary message builders for check-in notifications.
"""

from __future__ import annotations

from datetime import datetime
from html import escape


def _build_status(success_count: int, total_count: int) -> str:
    if total_count <= 0:
        return "unknown"
    if success_count == total_count:
        return "success"
    if success_count > 0:
        return "partial"
    return "failed"


def _trim_items(items: list[str], max_items: int | None = 8) -> tuple[list[str], int]:
    if not items:
        return [], 0
    trimmed = [item for item in items if item]
    if not trimmed:
        return [], 0
    if max_items is None:
        return trimmed, 0
    shown = trimmed[:max_items]
    extra = len(trimmed) - len(shown)
    return shown, extra


def _format_items(items: list[str], max_items: int | None = 8) -> str:
    shown, extra = _trim_items(items, max_items=max_items)
    if not shown:
        return "-"

    content = "; ".join(shown)
    if extra > 0:
        content += f"; ... (+{extra})"
    return content


def _parse_ratio(value: str | None) -> tuple[int, int] | None:
    if not value:
        return None
    parts = str(value).split("/", maxsplit=1)
    if len(parts) != 2:
        return None
    left, right = parts[0].strip(), parts[1].strip()
    if not (left.isdigit() and right.isdigit()):
        return None
    numerator = int(left)
    denominator = int(right)
    if denominator <= 0:
        return None
    return numerator, denominator


def _build_metric_html(label: str, value: str) -> str:
    ratio = _parse_ratio(value)
    if not ratio:
        return (
            '<div class="metric-card">'
            f'<div class="metric-label">{escape(label)}</div>'
            f'<div class="metric-value">{escape(value)}</div>'
            "</div>"
        )

    numerator, denominator = ratio
    percent = max(0.0, min(100.0, (numerator / denominator) * 100.0))
    return (
        '<div class="metric-card">'
        f'<div class="metric-label">{escape(label)}</div>'
        f'<div class="metric-value">{escape(value)}</div>'
        f'<div class="metric-bar"><span style="width: {percent:.1f}%;"></span></div>'
        f'<div class="metric-sub">{percent:.1f}%</div>'
        "</div>"
    )


def _build_tag_list_html(items: list[str], max_items: int = 6) -> str:
    shown, extra = _trim_items(items, max_items=max_items)
    if not shown:
        return '<span class="tag empty">none</span>'
    tags = "".join(f'<span class="tag">{escape(item)}</span>' for item in shown)
    if extra > 0:
        tags += f'<span class="tag extra">+{extra} more</span>'
    return tags


def _build_list_section_html(title: str, items: list[str], max_items: int = 8) -> str:
    shown, extra = _trim_items(items, max_items=max_items)
    if not shown:
        return ""

    body = "".join(f"<li>{escape(item)}</li>" for item in shown)
    if extra > 0:
        body += f'<li class="muted">... (+{extra})</li>'

    return (
        '<section class="section">'
        f'<h3 class="section-title">{escape(title)}</h3>'
        f"<ul>{body}</ul>"
        "</section>"
    )


def _format_auth_rows(rows: list[dict[str, str]], max_rows: int = 40) -> tuple[list[dict[str, str]], int]:
    if not rows:
        return [], 0

    normalized: list[dict[str, str]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        account = str(row.get("account", "")).strip() or "-"
        method = str(row.get("method", "")).strip() or "-"
        cache = str(row.get("cache", "")).strip().lower() or "-"
        if cache not in {"hit", "miss", "stale", "-"}:
            cache = "-"
        result = str(row.get("result", "")).strip().lower() or "-"
        if result not in {"ok", "fail", "-"}:
            result = "-"
        detail = str(row.get("detail", "")).strip() or "-"
        normalized.append(
            {
                "account": account,
                "method": method,
                "cache": cache,
                "result": result,
                "detail": detail,
            }
        )

    shown = normalized[:max_rows]
    extra = len(normalized) - len(shown)
    return shown, extra


def _build_auth_table_html(rows: list[dict[str, str]], empty_message: str) -> str:
    if not rows:
        return f'<p class="muted">{escape(empty_message)}</p>'

    status_colors = {
        "hit": "cache-hit",
        "miss": "cache-miss",
        "stale": "cache-stale",
        "-": "cache-na",
    }
    result_colors = {
        "ok": "result-ok",
        "fail": "result-fail",
        "-": "result-na",
    }

    body = []
    for row in rows:
        cache_cls = status_colors.get(row["cache"], "cache-na")
        result_cls = result_colors.get(row["result"], "result-na")
        body.append(
            "<tr>"
            f"<td>{escape(row['account'])}</td>"
            f"<td>{escape(row['method'])}</td>"
            f"<td><span class=\"badge {cache_cls}\">{escape(row['cache'])}</span></td>"
            f"<td><span class=\"badge {result_cls}\">{escape(row['result'])}</span></td>"
            f"<td>{escape(row['detail'])}</td>"
            "</tr>"
        )

    return (
        '<div class="table-wrap">'
        '<table class="auth-table">'
        "<colgroup>"
        '<col class="col-account" />'
        '<col class="col-method" />'
        '<col class="col-cache" />'
        '<col class="col-result" />'
        '<col class="col-detail" />'
        "</colgroup>"
        "<thead>"
        "<tr>"
        "<th>Account</th>"
        "<th>Auth Method</th>"
        "<th>Cache</th>"
        "<th>Result</th>"
        "<th>Detail</th>"
        "</tr>"
        "</thead>"
        f"<tbody>{''.join(body)}</tbody>"
        "</table>"
        "</div>"
    )


def _format_cache_rows(rows: list[dict[str, str]], max_rows: int = 20) -> tuple[list[dict[str, str]], int]:
    if not rows:
        return [], 0

    normalized: list[dict[str, str]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        account = str(row.get("account", "")).strip() or "-"
        method = str(row.get("method", "")).strip() or "-"
        cache = str(row.get("cache", "")).strip().lower() or "-"
        if cache not in {"hit", "miss", "stale", "-"}:
            cache = "-"
        result = str(row.get("result", "")).strip().lower() or "-"
        if result not in {"ok", "fail", "-"}:
            result = "-"
        detail = str(row.get("detail", "")).strip() or "-"
        normalized.append(
            {
                "account": account,
                "method": method,
                "cache": cache,
                "result": result,
                "detail": detail,
            }
        )

    shown = normalized[:max_rows]
    extra = len(normalized) - len(shown)
    return shown, extra


def _escape_markdown_cell(value: str) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ").strip()
    if not text:
        return "-"
    return text.replace("|", "\\|")


def _build_text_table(rows: list[dict[str, str]]) -> list[str]:
    data_rows = rows or [{"account": "-", "method": "-", "cache": "-", "result": "-", "detail": "-"}]
    lines = [
        "| Account | Auth Method | Cache | Result | Detail |",
        "| --- | --- | --- | --- | --- |",
    ]
    for row in data_rows:
        lines.append(
            "| "
            + " | ".join(
                [
                    _escape_markdown_cell(row.get("account", "-")),
                    _escape_markdown_cell(row.get("method", "-")),
                    _escape_markdown_cell(row.get("cache", "-")),
                    _escape_markdown_cell(row.get("result", "-")),
                    _escape_markdown_cell(row.get("detail", "-")),
                ]
            )
            + " |"
        )
    return lines


def _build_cache_table_html(rows: list[dict[str, str]]) -> str:
    shown, extra = _format_cache_rows(rows, max_rows=24)
    if not shown:
        return '<p class="muted">No cache data for this run.</p>'

    status_colors = {
        "hit": "cache-hit",
        "miss": "cache-miss",
        "stale": "cache-stale",
        "-": "cache-na",
    }
    result_colors = {
        "ok": "result-ok",
        "fail": "result-fail",
        "-": "result-na",
    }

    body = []
    for row in shown:
        cache_cls = status_colors.get(row["cache"], "cache-na")
        result_cls = result_colors.get(row["result"], "result-na")
        body.append(
            "<tr>"
            f"<td>{escape(row['account'])}</td>"
            f"<td>{escape(row['method'])}</td>"
            f"<td><span class=\"badge {cache_cls}\">{escape(row['cache'])}</span></td>"
            f"<td><span class=\"badge {result_cls}\">{escape(row['result'])}</span></td>"
            f"<td>{escape(row['detail'])}</td>"
            "</tr>"
        )
    if extra > 0:
        body.append(
            "<tr>"
            "<td colspan=\"5\" class=\"muted\">"
            f"... (+{extra} more rows)"
            "</td>"
            "</tr>"
        )

    return (
        '<div class="table-wrap">'
        '<table class="cache-table">'
        "<thead>"
        "<tr>"
        "<th>Account</th>"
        "<th>Auth Method</th>"
        "<th>Cache</th>"
        "<th>Result</th>"
        "<th>Detail</th>"
        "</tr>"
        "</thead>"
        f"<tbody>{''.join(body)}</tbody>"
        "</table>"
        "</div>"
    )


def build_summary_html(
    workflow: str,
    success_count: int,
    total_count: int,
    metrics: dict[str, str] | None = None,
    reasons: list[str] | None = None,
    failed_items: list[str] | None = None,
    partial_items: list[str] | None = None,
    highlight_items: list[str] | None = None,
    auth_rows: list[dict[str, str]] | None = None,
    cache_rows: list[dict[str, str]] | None = None,
    cache_items: list[str] | None = None,
    now: datetime | None = None,
) -> str:
    """Build a styled HTML summary payload for notification channels."""

    now_time = now or datetime.now()
    status = _build_status(success_count, total_count)
    failed_count = max(total_count - success_count, 0)

    status_map = {
        "success": ("SUCCESS", "#0f766e", "#ccfbf1"),
        "partial": ("PARTIAL", "#b45309", "#ffedd5"),
        "failed": ("FAILED", "#b91c1c", "#fee2e2"),
        "unknown": ("UNKNOWN", "#4b5563", "#e5e7eb"),
    }
    status_text, status_color, status_bg = status_map.get(status, status_map["unknown"])

    metric_pairs: list[tuple[str, str]] = [
        ("success", f"{success_count}/{total_count}"),
        ("failed", f"{failed_count}/{total_count}"),
    ]
    if metrics:
        metric_pairs.extend((str(key), str(value)) for key, value in metrics.items())

    metrics_html = "".join(_build_metric_html(label, value) for label, value in metric_pairs)
    reason_html = _build_tag_list_html(reasons or [], max_items=6)
    table_source = auth_rows or cache_rows or []
    if not table_source and cache_items:
        table_source = [{"account": "-", "method": "-", "cache": "-", "result": "-", "detail": item} for item in cache_items]
    normalized_rows, extra_rows = _format_auth_rows(table_source, max_rows=48)
    success_rows = [row for row in normalized_rows if row["result"] == "ok"]
    fail_rows = [row for row in normalized_rows if row["result"] == "fail"]
    if extra_rows > 0:
        fail_rows.append(
            {
                "account": f"... (+{extra_rows} more rows)",
                "method": "-",
                "cache": "-",
                "result": "-",
                "detail": "-",
            }
        )
    success_table_html = _build_auth_table_html(success_rows, "No successful auth rows.")
    fail_table_html = _build_auth_table_html(fail_rows, "No failed auth rows.")

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Check-in Summary</title>
  <style>
    :root {{
      --bg: #f3f7fb;
      --panel: #ffffff;
      --ink: #10253f;
      --line: #d8e4f0;
      --accent: #1167b1;
      --accent-soft: #dceeff;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background:
        radial-gradient(circle at 15% 20%, rgba(17, 103, 177, 0.08), transparent 36%),
        radial-gradient(circle at 85% 12%, rgba(13, 148, 136, 0.10), transparent 40%),
        var(--bg);
      color: var(--ink);
      font-family: "Trebuchet MS", "Segoe UI", "Noto Sans", sans-serif;
      padding: 26px 14px;
    }}
    .container {{
      max-width: 860px;
      margin: 0 auto;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 18px;
      overflow: hidden;
      box-shadow: 0 20px 48px rgba(16, 37, 63, 0.10);
    }}
    .hero {{
      padding: 22px 24px 18px;
      background:
        linear-gradient(120deg, rgba(17, 103, 177, 0.08), rgba(13, 148, 136, 0.12)),
        linear-gradient(180deg, #ffffff 0%, #f5fbff 100%);
      border-bottom: 1px solid var(--line);
    }}
    .title {{
      margin: 0;
      font-size: 28px;
      line-height: 1.2;
      letter-spacing: 0.3px;
      font-weight: 800;
    }}
    .meta {{
      margin-top: 10px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      font-size: 13px;
      color: #35516e;
    }}
    .meta-main {{
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
    }}
    .meta-item {{
      display: inline-flex;
      align-items: center;
      gap: 4px;
    }}
    .pill {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 7px 11px;
      border-radius: 999px;
      background: {status_bg};
      color: {status_color};
      font-weight: 700;
      font-size: 12px;
      letter-spacing: 0.4px;
    }}
    .content {{
      padding: 20px 24px 24px;
      display: grid;
      gap: 16px;
    }}
    .metrics {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 10px;
    }}
    .metric-card {{
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 10px 11px;
      background: #ffffff;
      min-height: 90px;
    }}
    .metric-label {{
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.7px;
      color: #5a7590;
      font-weight: 700;
    }}
    .metric-value {{
      margin-top: 5px;
      font-size: 24px;
      line-height: 1.1;
      font-weight: 800;
      color: #0f2944;
    }}
    .metric-sub {{
      margin-top: 5px;
      font-size: 12px;
      color: #5a7590;
    }}
    .metric-bar {{
      margin-top: 7px;
      height: 5px;
      border-radius: 999px;
      background: #e7eff8;
      overflow: hidden;
    }}
    .metric-bar > span {{
      display: block;
      height: 100%;
      background: linear-gradient(90deg, var(--accent), #0d9488);
    }}
    .section {{
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 12px 14px;
      background: #fff;
    }}
    .section-title {{
      margin: 0 0 8px;
      font-size: 15px;
      letter-spacing: 0.3px;
      color: #16304b;
    }}
    .tag-row {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }}
    .tag {{
      display: inline-block;
      border-radius: 999px;
      background: var(--accent-soft);
      color: #0e4f8a;
      font-size: 12px;
      font-weight: 700;
      padding: 5px 9px;
    }}
    .tag.extra {{
      background: #e5e7eb;
      color: #374151;
    }}
    .tag.empty {{
      background: #eef2f7;
      color: #6b7280;
      font-weight: 600;
    }}
    .table-wrap {{
      overflow: auto;
      border: 1px solid var(--line);
      border-radius: 10px;
      background: #fff;
    }}
    .auth-table {{
      width: 100%;
      border-collapse: collapse;
      table-layout: fixed;
      min-width: 640px;
    }}
    .auth-table col.col-account {{ width: 24%; }}
    .auth-table col.col-method {{ width: 18%; }}
    .auth-table col.col-cache {{ width: 11%; }}
    .auth-table col.col-result {{ width: 11%; }}
    .auth-table col.col-detail {{ width: 36%; }}
    .auth-table th,
    .auth-table td {{
      border-bottom: 1px solid #e7edf4;
      padding: 9px 10px;
      text-align: left;
      vertical-align: middle;
      font-size: 13px;
      line-height: 1.45;
      color: #1f3a57;
      word-break: break-word;
    }}
    .auth-table thead th {{
      background: #f5f9ff;
      color: #234767;
      font-weight: 700;
      font-size: 12px;
      letter-spacing: 0.3px;
      text-transform: uppercase;
    }}
    .auth-table tbody tr:last-child td {{
      border-bottom: none;
    }}
    .badge {{
      display: inline-block;
      border-radius: 999px;
      padding: 2px 8px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.2px;
      text-transform: uppercase;
    }}
    .cache-hit {{ background: #d1fae5; color: #065f46; }}
    .cache-miss {{ background: #dbeafe; color: #1e40af; }}
    .cache-stale {{ background: #ffedd5; color: #9a3412; }}
    .cache-na {{ background: #e5e7eb; color: #4b5563; }}
    .result-ok {{ background: #ccfbf1; color: #115e59; }}
    .result-fail {{ background: #fee2e2; color: #991b1b; }}
    .result-na {{ background: #e5e7eb; color: #4b5563; }}
    ul {{
      margin: 0;
      padding-left: 18px;
    }}
    li {{
      margin: 6px 0;
      line-height: 1.5;
      color: #1f3a57;
      word-break: break-word;
    }}
    .muted {{
      color: #6b7280;
      font-size: 13px;
      margin: 0;
    }}
    @media (max-width: 620px) {{
      .meta {{
        flex-direction: column;
        align-items: flex-start;
      }}
      .pill {{
        align-self: flex-start;
      }}
    }}
  </style>
</head>
<body>
  <main class="container">
    <header class="hero">
      <h1 class="title">Check-in Summary</h1>
      <div class="meta">
        <div class="meta-main">
          <span class="meta-item"><strong>workflow:</strong> {escape(workflow)}</span>
          <span class="meta-item"><strong>time:</strong> {now_time.strftime('%Y-%m-%d %H:%M:%S')}</span>
        </div>
        <span class="pill">{status_text}</span>
      </div>
    </header>
    <section class="content">
      <section class="metrics">
        {metrics_html}
      </section>
      <section class="section">
        <h3 class="section-title">Trigger</h3>
        <div class="tag-row">
          {reason_html}
        </div>
      </section>
      <section class="section">
        <h3 class="section-title">Successful Auth</h3>
        {success_table_html}
      </section>
      <section class="section">
        <h3 class="section-title">Failed Auth</h3>
        {fail_table_html}
      </section>
    </section>
  </main>
</body>
</html>"""


def build_summary_message(
    workflow: str,
    success_count: int,
    total_count: int,
    metrics: dict[str, str] | None = None,
    reasons: list[str] | None = None,
    failed_items: list[str] | None = None,
    partial_items: list[str] | None = None,
    balance_items: list[str] | None = None,
    highlight_items: list[str] | None = None,
    auth_rows: list[dict[str, str]] | None = None,
    cache_rows: list[dict[str, str]] | None = None,
    cache_items: list[str] | None = None,
    now: datetime | None = None,
) -> str:
    """Build a plain text summary payload for notification channels."""

    now_time = now or datetime.now()
    status = _build_status(success_count, total_count)
    failed_count = max(total_count - success_count, 0)

    lines = [
        "[Check-in Summary]",
        f"time: {now_time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"workflow: {workflow}",
        f"status: {status}",
        f"success: {success_count}/{total_count}",
        f"failed: {failed_count}/{total_count}",
    ]

    if metrics:
        for key, value in metrics.items():
            lines.append(f"{key}: {value}")

    if reasons:
        lines.append(f"trigger: {_format_items(reasons, max_items=6)}")

    table_source = auth_rows or cache_rows or []
    if not table_source and cache_items:
        table_source = [{"account": "-", "method": "-", "cache": "-", "result": "-", "detail": item} for item in cache_items]
    if not table_source:
        for item in highlight_items or []:
            table_source.append({"account": "-", "method": "-", "cache": "-", "result": "ok", "detail": item})
        for item in balance_items or []:
            table_source.append({"account": "-", "method": "-", "cache": "-", "result": "ok", "detail": item})
        for item in failed_items or []:
            table_source.append({"account": "-", "method": "-", "cache": "-", "result": "fail", "detail": item})
        for item in partial_items or []:
            table_source.append({"account": "-", "method": "-", "cache": "-", "result": "fail", "detail": item})

    shown, extra = _format_auth_rows(table_source, max_rows=48)
    success_rows = [row for row in shown if row["result"] == "ok"]
    fail_rows = [row for row in shown if row["result"] == "fail"]
    if extra > 0:
        fail_rows.append(
            {
                "account": f"... (+{extra} more rows)",
                "method": "-",
                "cache": "-",
                "result": "-",
                "detail": "-",
            }
        )

    lines.append("successful_auth:")
    lines.extend(_build_text_table(success_rows))
    lines.append("failed_auth:")
    lines.extend(_build_text_table(fail_rows))

    return "\n".join(lines)
