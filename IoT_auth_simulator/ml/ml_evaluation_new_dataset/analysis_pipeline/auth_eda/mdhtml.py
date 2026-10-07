"""Minimal Markdown → HTML for the report (headings, paragraphs, lists, tables,
fenced code, images, bold/italic/code/links). Avoids a `markdown` dependency.
Images are inlined as base64 so report.html is a single portable file."""
from __future__ import annotations

import base64
import html
import re
from pathlib import Path

_INLINE = [
    (re.compile(r"`([^`]+)`"), r"<code>\1</code>"),
    (re.compile(r"\*\*([^*]+)\*\*"), r"<strong>\1</strong>"),
    (re.compile(r"(?<![*\w])\*([^*\s][^*]*)\*(?!\w)"), r"<em>\1</em>"),
    (re.compile(r"\[([^\]]+)\]\(([^)]+)\)"), r'<a href="\2">\1</a>'),
]


def _inline(text: str) -> str:
    # Protect code spans from the other rules.
    parts = re.split(r"(`[^`]+`)", text)
    out = []
    for p in parts:
        if p.startswith("`") and p.endswith("`") and len(p) > 1:
            out.append(f"<code>{html.escape(p[1:-1])}</code>")
        else:
            s = html.escape(p, quote=False)
            for rx, rep in _INLINE[1:]:
                s = rx.sub(rep, s)
            out.append(s)
    return "".join(out)


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def convert(md: str, base_dir: Path) -> tuple[str, list[tuple[int, str, str]]]:
    lines = md.split("\n")
    out, toc = [], []
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("```"):
            j = i + 1
            while j < len(lines) and not lines[j].startswith("```"):
                j += 1
            out.append("<pre><code>" + html.escape("\n".join(lines[i + 1:j])) + "</code></pre>")
            i = j + 1
            continue
        m = re.match(r"^(#{1,4})\s+(.*)$", line)
        if m:
            level, text = len(m.group(1)), m.group(2)
            sid = _slug(text)
            if level in (2, 3):
                toc.append((level, sid, text))
            out.append(f'<h{level} id="{sid}">{_inline(text)}</h{level}>')
            i += 1
            continue
        m = re.match(r"^!\[([^\]]*)\]\(([^)]+)\)\s*$", line)
        if m:
            alt, src = m.groups()
            p = base_dir / src
            data = base64.b64encode(p.read_bytes()).decode() if p.exists() else ""
            out.append(f'<figure><img alt="{html.escape(alt)}" src="data:image/png;base64,{data}">'
                       f"<figcaption>{_inline(alt)}</figcaption></figure>")
            i += 1
            continue
        if line.startswith("|"):
            block = []
            while i < len(lines) and lines[i].startswith("|"):
                block.append(lines[i])
                i += 1
            rows = [[c.strip() for c in r.strip().strip("|").split("|")] for r in block]
            head, body = rows[0], [r for r in rows[1:] if not all(re.fullmatch(r":?-+:?", c) for c in r)]
            t = ['<div class="tbl"><table><thead><tr>' + "".join(f"<th>{_inline(c)}</th>" for c in head) + "</tr></thead><tbody>"]
            for r in body:
                t.append("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in r) + "</tr>")
            out.append("".join(t) + "</tbody></table></div>")
            continue
        if re.match(r"^\s*([-*]|\d+\.)\s+", line):
            ordered = bool(re.match(r"^\s*\d+\.", line))
            tag = "ol" if ordered else "ul"
            items = []
            while i < len(lines) and (re.match(r"^\s*([-*]|\d+\.)\s+", lines[i])
                                      or (lines[i].startswith("  ") and lines[i].strip() and items)):
                if re.match(r"^\s*([-*]|\d+\.)\s+", lines[i]):
                    items.append(re.sub(r"^\s*([-*]|\d+\.)\s+", "", lines[i]))
                else:
                    items[-1] += " " + lines[i].strip()
                i += 1
            out.append(f"<{tag}>" + "".join(f"<li>{_inline(x)}</li>" for x in items) + f"</{tag}>")
            continue
        if line.startswith("> "):
            block = []
            while i < len(lines) and lines[i].startswith(">"):
                block.append(lines[i][1:].strip())
                i += 1
            out.append('<aside class="callout">' + " ".join(_inline(b) if b else "<br>" for b in block) + "</aside>")
            continue
        if not line.strip():
            i += 1
            continue
        para = []
        while i < len(lines) and lines[i].strip() and not re.match(r"^(#|\||```|!\[|> |\s*([-*]|\d+\.)\s)", lines[i]):
            para.append(lines[i].strip())
            i += 1
        out.append("<p>" + _inline(" ".join(para)) + "</p>")
    return "\n".join(out), toc


CSS = """
:root{--bg:#f9f9f7;--surface:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;--muted:#898781;--line:#e1e0d9;--accent:#2a78d6;--code:#f0efec;--callout:#eef4fc}
@media (prefers-color-scheme: dark){:root:not([data-theme="light"]){--bg:#0d0d0d;--surface:#1a1a19;--ink:#fff;--ink2:#c3c2b7;--muted:#898781;--line:#2c2c2a;--accent:#3987e5;--code:#262624;--callout:#16233a}}
:root[data-theme="dark"]{--bg:#0d0d0d;--surface:#1a1a19;--ink:#fff;--ink2:#c3c2b7;--muted:#898781;--line:#2c2c2a;--accent:#3987e5;--code:#262624;--callout:#16233a}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif}
.layout{display:grid;grid-template-columns:260px minmax(0,1fr);max-width:1280px;margin:0 auto}
nav{position:sticky;top:0;height:100vh;overflow:auto;padding:24px 16px;border-right:1px solid var(--line);font-size:13px}
nav a{display:block;color:var(--ink2);text-decoration:none;padding:3px 0}
nav a.l3{padding-left:14px;color:var(--muted)}
nav a:hover{color:var(--accent)}
main{padding:32px 40px 80px;min-width:0}
h1{font-size:28px;margin:0 0 4px}h2{font-size:21px;margin:44px 0 10px;padding-top:12px;border-top:1px solid var(--line)}
h3{font-size:16.5px;margin:26px 0 8px}h4{font-size:14.5px;margin:18px 0 6px;color:var(--ink2)}
p,li{color:var(--ink);max-width:80ch}
a{color:var(--accent)}
code{background:var(--code);padding:1px 5px;border-radius:4px;font-size:.88em}
pre{background:var(--code);padding:12px 14px;border-radius:8px;overflow:auto;font-size:12.5px;line-height:1.45}
pre code{background:none;padding:0}
figure{margin:18px 0;background:#fcfcfb;border:1px solid var(--line);border-radius:10px;padding:10px}
figure img{max-width:100%;height:auto;display:block;margin:0 auto}
figcaption{font-size:12.5px;color:#52514e;padding:6px 4px 0}
.tbl{overflow-x:auto;margin:12px 0}
table{border-collapse:collapse;font-size:12.5px;font-variant-numeric:tabular-nums}
th,td{border-bottom:1px solid var(--line);padding:5px 10px;text-align:left;vertical-align:top}
th{color:var(--ink2);font-weight:600;background:var(--surface)}
.callout{background:var(--callout);border-left:3px solid var(--accent);padding:10px 14px;border-radius:6px;margin:14px 0;max-width:86ch}
@media (max-width:860px){.layout{grid-template-columns:1fr}nav{display:none}main{padding:20px 16px 60px}}
"""


def page(title: str, body: str, toc) -> str:
    nav = "".join(f'<a class="l{lv}" href="#{sid}">{html.escape(re.sub(r"[`*]", "", t))}</a>' for lv, sid, t in toc)
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f"<title>{html.escape(title)}</title><style>{CSS}</style></head>"
            f'<body><div class="layout"><nav><strong>Contents</strong>{nav}</nav><main>{body}</main></div></body></html>')
