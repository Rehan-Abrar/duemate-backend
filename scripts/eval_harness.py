#!/usr/bin/env python3
"""
DueMate Evaluation Harness
===========================
Runs the task parser against a diverse set of 24 real-world student messages
and produces a markdown accuracy / latency report.

Usage (from duemate-backend/):
    python scripts/eval_harness.py             # uses regex fallback (no API key needed)
    GROQ_API_KEY=gsk_... python scripts/eval_harness.py  # uses live Groq AI

Output:
    scripts/eval_report.md  (overwritten each run)
"""

import os
import sys
import time
import json
from datetime import datetime, timezone

# ─── Path setup ──────────────────────────────────────────────────────────────
BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BACKEND_DIR)

from utils.parse_task import parse_task  # noqa: E402

# ─── Ground-truth test dataset (24 diverse student messages) ─────────────────
# Each entry: (message, expected_task_type, expected_course_keyword, expect_due_date)
TEST_CASES = [
    # ── Assignments ───────────────────────────────────────────────────────────
    ("PDC assignment submit karna hai friday tak",
     "assignment", "pdc", True),
    ("Advanced DBMS assignment 3 due on 12 July 2026",
     "assignment", "dbms", True),
    ("guys cn ka project 30 June 2026 tak jama karwana hai please note karlo",
     "assignment", "computer networks", True),
    ("AI driven SE project due on 25 June 2026 before 5PM",
     "assignment", "ai", True),
    ("Submit Theory of Automata assignment before Monday midnight",
     "assignment", "automata", True),
    ("Here is complete assignment 4, student need to submit on 22 June 2026 before 2PM in my office",
     "assignment", None, True),
    ("entrepreneurship lab report due next wednesday",
     "assignment", "entrepreneurship", True),
    ("adbms lab assignment submit karein 15 july tak",
     "assignment", "dbms", True),
    ("Computer Networks assignment #2 is due on July 5, 11:59PM",
     "assignment", "computer networks", True),
    ("Problem Solving 3 homework due kal",
     "assignment", None, True),
    # ── Quizzes ───────────────────────────────────────────────────────────────
    ("kal TOA ka quiz hai chapter 3 aur 4 se",
     "quiz", "automata", True),
    ("Sir said next week AI class quiz related to neural networks and backprop",
     "quiz", "ai", False),
    ("Computer Networks Lab Exam 21 June Friday 2-5pm",
     "quiz", "computer networks", True),
    ("PDC quiz tomorrow morning 9am chapter 5",
     "quiz", "pdc", True),
    ("dbms quiz on ER diagrams next monday",
     "quiz", "dbms", True),
    ("quiz of automata will be on Monday",
     "quiz", "automata", True),
    ("entrepreneurship quiz hai kal slides 10 se 20 tak",
     "quiz", "entrepreneurship", True),
    ("AI driven software development quiz next class on transformers",
     "quiz", "ai", False),
    # ── Edge cases ────────────────────────────────────────────────────────────
    ("Assignment 3 Deadline: tomorrow 12PM",
     "assignment", None, True),
    ("Submit assignment before 2PM on 25 June 2026",
     "assignment", None, True),
    ("tmr ADBMS test hai chapter 2 se",
     "quiz", "dbms", True),
    ("quiz kal hai parha lo",
     "quiz", None, True),
    ("CN lab viva on friday",
     "quiz", "computer networks", True),
    ("AISD project milestone 2 due 30 june",
     "assignment", "ai", True),
]

# ─── Helpers ─────────────────────────────────────────────────────────────────

def _course_match(course_value: str | None, keyword: str | None) -> bool:
    """Return True if the extracted course contains the expected keyword."""
    if keyword is None:
        return True  # no assertion needed
    if not course_value:
        return False
    return keyword.lower() in course_value.lower()


def _run_tests() -> list[dict]:
    results = []
    for idx, (msg, exp_type, exp_course_kw, exp_has_date) in enumerate(TEST_CASES, 1):
        t0 = time.perf_counter()
        result = parse_task(msg)
        latency_ms = (time.perf_counter() - t0) * 1000

        type_ok = result["task_type"] == exp_type
        course_ok = _course_match(result.get("course"), exp_course_kw)
        date_ok = (result.get("due_date") is not None) == exp_has_date

        passed = type_ok and course_ok and date_ok
        results.append({
            "idx": idx,
            "message": msg[:70] + ("…" if len(msg) > 70 else ""),
            "passed": passed,
            "type_ok": type_ok,
            "course_ok": course_ok,
            "date_ok": date_ok,
            "got_type": result.get("task_type", "-"),
            "got_course": result.get("course") or "(none)",
            "got_date": result.get("due_date").strftime("%Y-%m-%d %H:%M UTC") if result.get("due_date") else "(none)",
            "confidence": round(result.get("confidence", 0), 2),
            "parse_method": result.get("parse_method", "-"),
            "latency_ms": round(latency_ms, 1),
            "needs_review": result.get("needs_review", False),
        })
    return results


def _write_report(results: list[dict]) -> str:
    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    type_ok = sum(1 for r in results if r["type_ok"])
    course_ok = sum(1 for r in results if r["course_ok"])
    date_ok = sum(1 for r in results if r["date_ok"])
    avg_lat = sum(r["latency_ms"] for r in results) / total
    avg_conf = sum(r["confidence"] for r in results) / total
    parse_methods = {}
    for r in results:
        parse_methods[r["parse_method"]] = parse_methods.get(r["parse_method"], 0) + 1

    pct = lambda n: f"{n}/{total} ({100*n//total}%)"  # noqa: E731

    lines = [
        "# DueMate Evaluation Harness Report",
        "",
        f"> Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "## 📊 Summary",
        "",
        f"| Metric | Value |",
        f"|:---|:---|",
        f"| **Overall Pass Rate** | {pct(passed)} |",
        f"| Task Type Accuracy | {pct(type_ok)} |",
        f"| Course Extraction Accuracy | {pct(course_ok)} |",
        f"| Due Date Extraction Accuracy | {pct(date_ok)} |",
        f"| Avg Latency | {avg_lat:.0f} ms |",
        f"| Avg Confidence Score | {avg_conf:.2f} |",
        f"| Parse Methods | {json.dumps(parse_methods)} |",
        "",
        "## 🧪 Test Case Results",
        "",
        "| # | Pass | Message | Type ✓ | Course ✓ | Date ✓ | Confidence | Latency | Method |",
        "|---|:---:|---|:---:|:---:|:---:|:---:|---:|---|",
    ]

    for r in results:
        icon = "✅" if r["passed"] else "❌"
        t = "✅" if r["type_ok"] else "❌"
        c = "✅" if r["course_ok"] else "⚠️"
        d = "✅" if r["date_ok"] else "❌"
        lines.append(
            f"| {r['idx']} | {icon} | `{r['message']}` | {t} | {c} | {d} "
            f"| {r['confidence']} | {r['latency_ms']}ms | {r['parse_method']} |"
        )

    lines += [
        "",
        "## 📋 Detailed Results",
        "",
    ]
    for r in results:
        status = "PASS" if r["passed"] else "FAIL"
        lines += [
            f"### [{status}] #{r['idx']}: `{r['message']}`",
            f"- **Type**: `{r['got_type']}`  |  **Course**: `{r['got_course']}`  |  **Due Date**: `{r['got_date']}`",
            f"- **Confidence**: {r['confidence']}  |  **Needs Review**: {r['needs_review']}  |  **Latency**: {r['latency_ms']}ms",
            "",
        ]

    return "\n".join(lines)


def main():
    use_groq = bool(os.getenv("GROQ_API_KEY"))
    print(f"DueMate Evaluation Harness — {'Groq AI' if use_groq else 'Regex Fallback'} mode")
    print(f"Running {len(TEST_CASES)} test cases...\n")

    results = _run_tests()

    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    print(f"Results: {passed}/{total} passed ({100*passed//total}%)")
    for r in results:
        label = "PASS" if r["passed"] else "FAIL"
        print(f"  {label} #{r['idx']:02d} [{r['parse_method'][:5]}] {r['message'][:60]}")

    report_path = os.path.join(os.path.dirname(__file__), "eval_report.md")
    report = _write_report(results)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"\nReport written to: {report_path}")
    return 0 if passed / total >= 0.8 else 1


if __name__ == "__main__":
    sys.exit(main())
