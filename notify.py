import json
import os
import pathlib
import subprocess
import sys

import requests

TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN")
TG_CHAT_ID   = os.environ.get("TG_CHAT_ID")

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "none":     "⚪",
}


def _new_report_paths() -> list[str]:
    result = subprocess.run(
        ["git", "status", "--porcelain", "reports/"],
        capture_output=True, text=True,
    )
    paths = []
    for line in result.stdout.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            path = parts[1].strip()
            if path.endswith(".json") and os.path.exists(path):
                paths.append(path)
    return paths


def _html(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _bounty_emoji(amount: float) -> str:
    if amount >= 2000:
        return "🤑"
    if amount >= 500:
        return "💰"
    return "💸"


def _category_from_path(path: str) -> str:
    parts = pathlib.Path(path).parts
    # reports/{category}/...
    idx = next((i for i, p in enumerate(parts) if p == "reports"), -1)
    if idx >= 0 and idx + 1 < len(parts):
        return parts[idx + 1]
    return ""


def _format(report: dict, path: str) -> str:
    title     = report.get("title") or "Untitled"
    url       = report.get("url") or ""
    sev_raw   = (report.get("severity_rating") or "none").lower()
    sev_emoji = SEVERITY_EMOJI.get(sev_raw, "⚪")
    cwe       = (report.get("weakness") or {}).get("name") or "Unknown"
    amount    = float(report.get("bounty_amount") or 0)
    bounty    = report.get("formatted_bounty") or f"${amount:,.0f}"
    category  = _category_from_path(path)
    tags      = f"#h1 #{category}" if category else "#h1"

    return "\n".join([
        f'{sev_emoji} <a href="{url}">{_html(title)}</a>',
        "",
        f"🎯 CWE: {_html(cwe)}",
        f"{_bounty_emoji(amount)} Amount: {_html(bounty)}",
        "",
        tags,
    ])


def _send(text: str) -> None:
    resp = requests.post(
        f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage",
        json={
            "chat_id":                  TG_CHAT_ID,
            "text":                     text,
            "parse_mode":               "HTML",
            "disable_web_page_preview": True,
        },
        timeout=15,
    )
    resp.raise_for_status()


def main() -> None:
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        print("TG_BOT_TOKEN or TG_CHAT_ID not configured — skipping notifications.")
        return

    paths = sys.argv[1:] if len(sys.argv) > 1 else _new_report_paths()
    if not paths:
        print("No new report files found.")
        return

    sent = skipped = failed = 0
    for path in paths:
        try:
            with open(path, encoding="utf-8") as f:
                report = json.load(f)

            bounty = float(report.get("bounty_amount") or 0)
            if bounty <= 0:
                skipped += 1
                continue

            _send(_format(report, path))
            print(f"  sent: {report.get('url', path)}  ({report.get('formatted_bounty', f'${bounty:,.0f}')})")
            sent += 1

        except Exception as e:
            print(f"  ERROR {path}: {e}")
            failed += 1

    print(f"\nDone. sent={sent}  skipped={skipped}  failed={failed}")


if __name__ == "__main__":
    main()
