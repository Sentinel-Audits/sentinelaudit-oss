from __future__ import annotations

import json
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[2]
RESULTS_DIR = ROOT / "benchmarks" / "results"
SHARE_DIR = ROOT / "benchmarks" / "share"


def pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def load_latest_scorecard() -> tuple[Path, dict]:
    files = sorted(RESULTS_DIR.glob("*.json"), reverse=True)
    if not files:
        raise RuntimeError(f"No benchmark scorecards found in {RESULTS_DIR}")
    latest = files[0]
    return latest, json.loads(latest.read_text(encoding="utf-8"))


def load_font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = [
        "C:/Windows/Fonts/georgiab.ttf" if bold else "C:/Windows/Fonts/georgia.ttf",
        "C:/Windows/Fonts/arialbd.ttf" if bold else "C:/Windows/Fonts/arial.ttf",
    ]
    for path in candidates:
        try:
            return ImageFont.truetype(path, size=size)
        except OSError:
            continue
    return ImageFont.load_default()


def wrap_text(draw: ImageDraw.ImageDraw, text: str, font: ImageFont.ImageFont, max_width: int) -> list[str]:
    words = text.split()
    if not words:
        return [""]
    lines: list[str] = []
    current = words[0]
    for word in words[1:]:
        candidate = f"{current} {word}"
        if draw.textbbox((0, 0), candidate, font=font)[2] <= max_width:
            current = candidate
        else:
            lines.append(current)
            current = word
    lines.append(current)
    return lines


def draw_metric(
    draw: ImageDraw.ImageDraw,
    box: tuple[int, int, int, int],
    label: str,
    value: str,
    sub: str,
):
    x1, y1, x2, y2 = box
    draw.rounded_rectangle(box, radius=12, fill="#0A0A0A", outline="#27272A", width=2)
    draw.text((x1 + 22, y1 + 18), label.upper(), fill="#A1A1AA", font=FONT_LABEL)
    draw.text((x1 + 22, y1 + 48), value, fill="#FAFAFA", font=FONT_VALUE)
    draw.text((x1 + 22, y1 + 94), sub, fill="#D4D4D8", font=FONT_TEXT)


FONT_TITLE = load_font(44, bold=True)
FONT_SUBTITLE = load_font(18)
FONT_LABEL = load_font(18, bold=True)
FONT_VALUE = load_font(34, bold=True)
FONT_TEXT = load_font(18)
FONT_BODY = load_font(22)


def main():
    latest_path, scorecard = load_latest_scorecard()
    SHARE_DIR.mkdir(parents=True, exist_ok=True)

    width, height = 1600, 900
    image = Image.new("RGB", (width, height), "#000000")
    draw = ImageDraw.Draw(image)
    draw.line((80, 84, 1520, 84), fill="#27272A", width=1)
    draw.line((80, 822, 1520, 822), fill="#27272A", width=1)

    draw.text((80, 52), "SENTINELAUDIT BENCHMARK SNAPSHOT", fill="#FAFAFA", font=FONT_LABEL)
    draw.text((80, 108), "Security Workflow Benchmarking", fill="#FAFAFA", font=FONT_TITLE)
    draw.text(
        (80, 170),
        f"Generated {scorecard['generatedAt'][:10]} from deterministic benchmark suites and local audit telemetry.",
        fill="#A1A1AA",
        font=FONT_SUBTITLE,
    )

    repo = scorecard["repoBenchmarks"]
    auditor = scorecard["auditorReviewSet"]
    intelligence = scorecard["auditIntelligence"]

    draw_metric(
        draw,
        (80, 248, 420, 370),
        "Repo Benchmarks",
        pct(repo["bucketAccuracy"]),
        f"{repo['fixtures']} fixtures - {repo['cases']} cases",
    )
    draw_metric(
        draw,
        (450, 248, 790, 370),
        "Auditor Review Set",
        pct(auditor["headlineAccuracy"]),
        f"{auditor['cases']} reviewed cases",
    )
    draw_metric(
        draw,
        (820, 248, 1160, 370),
        "Provenance Coverage",
        pct(intelligence["provenanceCoverage"]),
        f"{intelligence['artifacts']} local artifacts",
    )
    draw_metric(
        draw,
        (1190, 248, 1530, 370),
        "Value-Flow Coverage",
        pct(intelligence["valueFlowCoverage"]),
        f"{intelligence['reportFindings']} report - {intelligence['needsReview']} review",
    )

    draw.rounded_rectangle((80, 430, 780, 780), radius=14, fill="#0A0A0A", outline="#27272A", width=2)
    draw.text((110, 464), "Public benchmark corpus", fill="#FAFAFA", font=FONT_LABEL)
    draw.text((110, 506), "Named fixtures and review focus areas that can be inspected directly.", fill="#A1A1AA", font=FONT_TEXT)
    corpus_lines = [
        f"{fixture['name']} ({fixture['cases']} cases)"
        for fixture in repo["fixtureBreakdown"][:4]
    ]
    y = 556
    for line in corpus_lines:
        draw.text((110, y), line, fill="#FAFAFA", font=FONT_BODY)
        y += 34
    draw.text((110, 690), "Auditor review focus", fill="#A1A1AA", font=FONT_TEXT)
    focus_lines = [f"{area['tag']} ({area['count']})" for area in auditor["focusAreas"][:4]]
    y = 724
    for line in focus_lines:
        draw.text((110, y), line, fill="#D4D4D8", font=FONT_TEXT)
        y += 28

    draw.rounded_rectangle((820, 430, 1530, 780), radius=14, fill="#0A0A0A", outline="#27272A", width=2)
    draw.text((850, 464), "Telemetry and method", fill="#FAFAFA", font=FONT_LABEL)
    top_signal = intelligence["topImprovementSignals"][0]["key"] if intelligence["topImprovementSignals"] else "none"
    top_mismatch = (
        intelligence["topDimensionalMismatchKinds"][0]["kind"]
        if intelligence["topDimensionalMismatchKinds"]
        else "none"
    )
    telemetry_lines = [
        f"{intelligence['artifacts']} local audit artifacts",
        f"{intelligence['reportFindings']} report findings / {intelligence['needsReview']} review findings",
        f"top signal: {top_signal}",
        f"top mismatch: {top_mismatch}",
    ]
    y = 516
    for line in telemetry_lines:
        draw.text((850, y), line, fill="#FAFAFA", font=FONT_TEXT)
        y += 30
    draw.text((850, 648), "Methodology", fill="#A1A1AA", font=FONT_TEXT)
    method_lines = [
        "Evidence layers",
        "1. curated repo benchmark fixtures",
        "2. auditor-aligned reviewset expectations",
        "3. anonymized production telemetry",
    ]
    y = 682
    for line in method_lines:
        draw.text((850, y), line, fill="#D4D4D8", font=FONT_TEXT)
        y += 28

    draw.text(
        (80, 844),
        "Public benchmark corpus is inspectable. Production telemetry is anonymized by default.",
        fill="#71717A",
        font=FONT_TEXT,
    )

    stem = latest_path.stem
    out_path = SHARE_DIR / f"{stem}.png"
    image.save(out_path, format="PNG")
    print("=== SentinelAudit Benchmark PNG ===")
    print(f"Source scorecard: {latest_path}")
    print(f"PNG card: {out_path}")


if __name__ == "__main__":
    main()
