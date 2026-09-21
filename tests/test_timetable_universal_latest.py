"""
Regression tests for the LATEST RSCI grid-format timetable PDF
(RSCI FALL 2026 v1.0 w.e.f. 21 September 2026).

What changed in this edition, and why these tests exist:
  * The room column holds BARE ROOM NUMBERS (210, 211, 117, ...) instead of
    names like "Classroom 1". The old room-row builder treated every number as
    a wrapped continuation of the previous label, collapsing all 23 rows into
    one - which made validate_layout() return False and rejected every upload.
  * Class cells are filled rectangles whose edges are the true start/end times;
    a shared lecture may list several sections at once, e.g. "(BSCS-7A, BSCS-7B)".

The PDF is vendored at tests/fixtures/Latest-Timetable.pdf and exposed by the
shared `latest_timetable_pdf` fixture in conftest.py, which fails loudly if it is
missing so a green run always means the parser was actually exercised.
"""

import os
import sys
from collections import Counter

import pytest

TEST_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if TEST_ROOT not in sys.path:
    sys.path.insert(0, TEST_ROOT)

from utils.timetable_universal import (  # noqa: E402
    UniversalTimetableParser,
    _parse_hhmm_minutes,
)

# Ground truth for BSCS-7B: (day, start, end, course, room)
EXPECTED_BSCS_7B = [
    ("Monday", "11:00 AM", "1:00 PM", "Computer Vision", "117"),
    ("Monday", "1:30 PM", "3:30 PM", "Compiler Construction", "210"),
    ("Tuesday", "11:00 AM", "1:00 PM",
     "Technology Venture Development & Management", "210"),
    ("Wednesday", "8:00 AM", "11:00 AM", "Information Security Lab", "318"),
    ("Wednesday", "1:00 PM", "3:00 PM", "Information Security", "314"),
    ("Thursday", "2:00 PM", "5:00 PM", "Computer Vision Lab", "311"),
    ("Friday", "10:30 AM", "1:00 PM", "Compiler Construction Lab", "318"),
]

# Monday's room column, top to bottom (from the PDF's left-hand strip).
EXPECTED_MONDAY_ROOMS = [
    "210", "211", "212", "213", "214", "217", "310", "314", "315", "409",
    "412", "413", "117", "311", "318", "323", "408", "410", "416", "417",
    "222", "205", "407",
]


@pytest.fixture(scope="module")
def parser(latest_timetable_pdf):
    with open(latest_timetable_pdf, "rb") as f:
        return UniversalTimetableParser(stream=f.read())


@pytest.fixture(scope="module")
def parsed(parser):
    """parse_all() is the expensive pass - run it once for the whole module."""
    return parser.parse_all()


def test_layout_is_accepted(parser):
    """Numeric room labels must not trip the layout gate (the upload blocker)."""
    assert parser.validate_layout() is True


def test_numeric_room_labels_are_separate_rows(parser):
    """Each bare number is its own room row - never one merged label.

    Pinning the whole set matters: BSCS-7B only uses 6 of the 23 rows, so a
    shifted/merged row elsewhere in the column would otherwise go unnoticed.
    """
    names = list(parser._rooms(parser.doc[0]).values())
    assert names == EXPECTED_MONDAY_ROOMS, (
        f"room rows mismatch ({len(names)} vs {len(EXPECTED_MONDAY_ROOMS)}): {names}"
    )


def test_bscs_7b_slots_match_truth(parsed):
    got = Counter(
        (s["day"], _parse_hhmm_minutes(s["start_time"]), _parse_hhmm_minutes(s["end_time"]),
         s["course"].strip(), s["room"].strip())
        for s in parsed.get("BSCS-7B", [])
    )
    expected = Counter(
        (day, _parse_hhmm_minutes(start), _parse_hhmm_minutes(end), course, room)
        for day, start, end, course, room in EXPECTED_BSCS_7B
    )
    assert got == expected, f"BSCS-7B mismatch\n  missing: {expected - got}\n  extra:   {got - expected}"


def test_all_sections_still_parse(parsed):
    """Room-row reconstruction feeds every section, not just BSCS-7B."""
    assert len(parsed) >= 30, f"only {len(parsed)} sections parsed: {sorted(parsed)[:5]}"
    assert "BSCS-7B" in parsed


def test_shared_section_cell_is_credited_to_every_section(parsed):
    """Tuesday's lecture lists '(BSCS-7A, BSCS-7B)' and belongs to both."""
    tvdm = "Technology Venture Development & Management"
    for section in ("BSCS-7A", "BSCS-7B"):
        courses = [s["course"] for s in parsed.get(section, [])]
        assert tvdm in courses, f"{section} missing the shared Tuesday lecture"
