"""The recoverability console: one page, rendered from a horizon.

Every retrospective metric in incident response answers a question about the
past. MTTD is how long it took to notice, MTTR how long it took to fix, and an
audit log says what already happened. None of them answers the only question
that can still change the outcome: **how long do you still have to undo this**.

That is the whole screen. It is deliberately not an agent observability
dashboard — there are five good open-source ones and this would be the sixth,
worse. It shows the thing none of them can, because none of them models
recoverability at all.

Why static HTML with nothing in it
----------------------------------
No server, no JavaScript, no fonts, no requests. A single file that opens from
disk, attaches to an incident ticket, and lands in an evidence pack unchanged.
The Go enforcer ships as a static binary from `scratch` for the same reason:
the fewer things that have to be running for this to be readable, the more
places it can be read.

It also means the page is honest about what it is — a snapshot, stamped with the
instant it was taken. A console that refreshes itself invites the reading that
what is on screen is true now. This one cannot be misread that way, because it
plainly cannot know.
"""

from __future__ import annotations

import html
import time
from typing import Any

from .reversal.horizon import Horizon, HorizonEntry

# Buckets in the order an operator needs them, not alphabetically. `broken`
# leads: an undo path with a hole in it reads as recoverable on every other
# view, and it is the one thing here that is actively misleading elsewhere.
_SECTIONS: tuple[tuple[str, str, str], ...] = (
    ("broken", "Claims an undo it cannot run",
     "A plan is recorded and it has a hole — an unresolved argument or a failed "
     "snapshot. Counted as recoverable by anything that trusts the classification."),
    ("closing", "Closing",
     "Undoable now, on a clock. Sorted by how little time is left."),
    ("standing_exposure", "Standing exposure",
     "Committed and never undoable. Not a window closing — a window that never was."),
    ("expired", "Expired",
     "There was a window and it closed. The undo is gone."),
    ("open_indefinitely", "Open indefinitely",
     "Undoable with nothing counting down. Not permanent: a gate can close and a "
     "drill can go stale."),
)


def _fmt_duration(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    if seconds < 0:
        return "closed"
    if seconds < 90:
        return f"{seconds:.0f}s"
    if seconds < 5400:
        return f"{seconds / 60:.0f}m"
    if seconds < 172800:
        return f"{seconds / 3600:.1f}h"
    return f"{seconds / 86400:.1f}d"


def _fmt_when(ts: float | None) -> str:
    if ts is None:
        return "—"
    return time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(ts))


def _e(text: Any) -> str:
    return html.escape(str(text), quote=True)


def _row(entry: HorizonEntry, *, urgent: bool) -> str:
    cls = ' class="urgent"' if urgent else ""
    gates = ", ".join(entry.gates) or "—"
    detail = entry.reason or entry.residue
    return (
        f"<tr{cls}>"
        f'<td class="tool">{_e(entry.tool)}</td>'
        f'<td>{_e(entry.kind.value)}</td>'
        f'<td class="num">{_e(_fmt_duration(entry.seconds_remaining))}</td>'
        f"<td>{_e(_fmt_when(entry.committed_at))}</td>"
        f"<td>{_e(entry.session_id or '—')}</td>"
        f"<td>{_e(gates)}</td>"
        f'<td class="detail">{_e(detail)}</td>'
        "</tr>"
    )


def render_html(horizon: Horizon, *, title: str = "Reversibility horizon",
                subject: str = "") -> str:
    """One self-contained page. No network, no script, no state."""
    ttc = horizon.time_to_first_close
    nxt = horizon.next_to_close
    total = horizon.undoable_count + horizon.unrecoverable_count

    if ttc is None or nxt is None:
        headline = "Nothing is counting down"
        sub = "No undo window has a deadline. That is not the same as safe."
    else:
        headline = f"{_fmt_duration(ttc)} until the first undo closes"
        sub = f"Next to go: {_e(nxt.tool)}"

    parts: list[str] = []
    for key, label, blurb in _SECTIONS:
        rows: tuple[HorizonEntry, ...] = getattr(horizon, key)
        if not rows:
            continue
        soon = {e.journal_id for e in horizon.closing_soon} if key == "closing" else set()
        body = "".join(_row(e, urgent=(key == "broken" or e.journal_id in soon))
                       for e in rows)
        parts.append(
            f'<section class="{_e(key)}">'
            f"<h2>{_e(label)} <span class=\"count\">{len(rows)}</span></h2>"
            f"<p class=\"blurb\">{_e(blurb)}</p>"
            '<div class="tw"><table><thead><tr>'
            "<th>Tool</th><th>Posture</th><th>Left</th><th>Committed</th>"
            "<th>Session</th><th>Gates</th><th>Detail</th>"
            "</tr></thead><tbody>" + body + "</tbody></table></div></section>"
        )

    notes = ""
    if horizon.notes:
        notes = ('<section class="notes"><h2>Notes</h2><ul>'
                 + "".join(f"<li>{_e(n)}</li>" for n in horizon.notes)
                 + "</ul></section>")

    if not parts:
        parts.append('<section><p class="empty">No committed actions in scope. '
                     "Nothing to recover and nothing standing.</p></section>")

    return _PAGE.format(
        title=_e(title),
        subject=f'<div class="subject">{_e(subject)}</div>' if subject else "",
        headline=_e(headline) if (ttc is None or nxt is None) else headline,
        sub=sub,
        undoable=horizon.undoable_count,
        total=total,
        pct=f"{horizon.recoverable_fraction:.0%}" if total else "—",
        broken=len(horizon.broken),
        # The tile turns red only when there is something in it. A permanently
        # coloured alarm is one people stop seeing.
        bad_broken=" bad" if horizon.broken else "",
        standing=len(horizon.standing_exposure),
        soon=len(horizon.closing_soon),
        warn=_fmt_duration(horizon.warn_within),
        at=_fmt_when(horizon.at),
        sections="".join(parts) + notes,
    )


_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
:root{{--bg:#ECEDEF;--card:#F7F8F9;--ink:#15181B;--mut:#5E656C;--rule:#CFD3D7;
--urg:#8A2A22;--urg-bg:rgba(138,42,34,.09);--ok:#1D5E4E}}
@media(prefers-color-scheme:dark){{:root{{--bg:#111316;--card:#191C20;--ink:#E6E8EA;
--mut:#929AA1;--rule:#2A2E33;--urg:#E88C80;--urg-bg:rgba(232,140,128,.12);--ok:#6FC3AA}}}}
*{{box-sizing:border-box}}
body{{margin:0;padding:0 20px 64px;background:var(--bg);color:var(--ink);
font:15px/1.55 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}}
.wrap{{max-width:1080px;margin:0 auto}}
header{{padding:52px 0 26px;border-bottom:2px solid var(--ink);margin-bottom:30px}}
.subject{{font-size:.74rem;letter-spacing:.14em;text-transform:uppercase;color:var(--mut);
margin-bottom:12px}}
h1{{margin:0;font-size:clamp(1.9rem,4.6vw,2.9rem);line-height:1.06;letter-spacing:-.02em}}
.sub{{margin-top:8px;color:var(--mut);font-size:1.02rem}}
.tiles{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;
margin:26px 0 8px}}
.tile{{background:var(--card);border:1px solid var(--rule);padding:14px 16px}}
.tile b{{display:block;font-size:1.7rem;line-height:1.1;font-variant-numeric:tabular-nums}}
.tile span{{display:block;margin-top:3px;font-size:.76rem;color:var(--mut);line-height:1.35}}
.tile.bad b{{color:var(--urg)}}
section{{margin-top:34px}}
h2{{margin:0;font-size:1.06rem;display:flex;align-items:baseline;gap:9px}}
.count{{font-size:.78rem;color:var(--mut);font-variant-numeric:tabular-nums}}
.blurb{{margin:5px 0 12px;color:var(--mut);font-size:.9rem;max-width:74ch}}
.tw{{overflow-x:auto;border:1px solid var(--rule);background:var(--card)}}
table{{border-collapse:collapse;width:100%;min-width:800px;font-size:.83rem}}
th,td{{padding:9px 12px;text-align:left;border-bottom:1px solid var(--rule);
vertical-align:top}}
th{{font-size:.66rem;letter-spacing:.08em;text-transform:uppercase;color:var(--mut)}}
tbody tr:last-child td{{border-bottom:none}}
td.num{{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}}
td.tool{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;white-space:nowrap}}
td.detail{{color:var(--mut);max-width:38ch}}
tr.urgent td{{background:var(--urg-bg)}}
tr.urgent td.num{{color:var(--urg);font-weight:600}}
.notes ul{{margin:0;padding-left:18px;color:var(--mut);font-size:.9rem}}
.empty{{color:var(--mut)}}
footer{{margin-top:52px;padding-top:18px;border-top:1px solid var(--rule);
color:var(--mut);font-size:.8rem}}
</style></head><body><div class="wrap">
<header>
{subject}<h1>{headline}</h1><div class="sub">{sub}</div>
<div class="tiles">
<div class="tile"><b>{undoable}/{total}</b><span>Recoverable now ({pct})</span></div>
<div class="tile{bad_broken}"><b>{broken}</b><span>Claim an undo they cannot run</span></div>
<div class="tile"><b>{standing}</b><span>Standing exposure — never undoable</span></div>
<div class="tile"><b>{soon}</b><span>Closing within {warn}</span></div>
</div>
</header>
{sections}
<footer>Snapshot taken {at}. This page does not refresh and cannot know anything
that happened after that instant — an undo window shown as open may have closed
since. Regenerate to ask again.</footer>
</div></body></html>
"""


__all__ = ["render_html"]
