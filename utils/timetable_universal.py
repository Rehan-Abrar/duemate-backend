"""
Universal Timetable Parser — Backend Edition
=============================================
Ported from Test/timetable_universal.py with the following additions:
  - Stream-based (in-memory) loading: no temp files on disk.
  - Layout validation: rejects PDFs that are not the supported grid format.
  - parse_all(): extracts slots for EVERY section found in the PDF.
  - get_all_sections(): returns the sorted list of detected section labels.

Supported format: Riphah University grid-format timetables (new campus).
  - Each page = one weekday (Mon–Fri).
  - Left column: room labels. Either names (Classroom 1, Computer Lab 2, FYP Lab,
    Physics Lab) or bare room numbers (210, 211, 117, ...) — the latest
    RSCI timetable uses numbers, one per row.
  - Top row: time columns (HH:MM + AM/PM, y < 110). Last printed header is
    4:30 PM; a class that occupies that column ends at 5:00 PM.
  - Cells: section markers (BSCS-7B etc.) + course name.
  - Class cells may be filled rectangles or unfilled (grid-line-only) cells.
"""

import fitz  # PyMuPDF
import re
import logging
from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional
from collections import defaultdict

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------------------

class InvalidTimetableLayoutError(ValueError):
    """Raised when the uploaded PDF does not match the expected grid format."""
    pass


# ---------------------------------------------------------------------------
# Section normalisation helpers
# ---------------------------------------------------------------------------

# Pattern used for SEARCHING (not fullmatch) inside raw text.
# Matches both  BSCS-6B  (digit + optional letter) and  BSCS-7  (digit only).
# The optional trailing letter distinguishes sections like 6A vs 6B.
_SEC_PATTERN = re.compile(
    r'(BSCS|BSSE|BSDS|BSIT|BSAI|BSCY|BSCGV|BSComp|BSCOMP)\s*[-\u2013]?\s*(\d+)\s*([A-Za-z])?',
    re.IGNORECASE,
)


def _norm_section(raw: str) -> str:
    """
    Normalise a raw section string to canonical form.
    'bscs 6 b'  -> 'BSCS-6B'
    '(BSCS-6B)' -> 'BSCS-6B'
    '(BSCS-7)'  -> 'BSCS-7'
    'BSAI-2M'   -> 'BSAI-2M'
    """
    clean = re.sub(r'[()\uff08\uff09\s,]', '', raw).upper()
    m = re.match(
        r'^(BSCS|BSSE|BSDS|BSIT|BSAI|BSCY|BSCGV|BSCOMP)'
        r'[-\u2013]?(\d+)([A-Z]?)$',
        clean, re.I,
    )
    if m:
        prog = m.group(1).upper()
        sem  = m.group(2)
        sec  = m.group(3).upper()
        label = f"{prog}-{sem}"
        if sec:
            label += sec
        return label
    return clean


def _extract_sections_from_text(text: str) -> List[str]:
    """
    Find all section labels in an arbitrary text string.
    Returns a list of normalised section labels.
    Uses search (not fullmatch) so it works on tokens that contain
    extra characters like commas, parentheses, or adjacent text.
    """
    found = []
    for m in _SEC_PATTERN.finditer(text):
        label = _norm_section(m.group(0))
        if label:
            found.append(label)
    return found


def _sections_in_words(words: List) -> List[Dict]:
    """
    Return list of {section, x, y, x0, x1, y0, y1} for every detected
    section marker in the word list.

    Strategy:
      A. Search each individual word token (catches '(BSCS-6B)' etc.).
      B. Slide a 2-token window to reconstruct labels split across tokens
         e.g. '(BSDS-6,' + 'BSCGV-7)' — each is a valid standalone match.
    """
    found = []
    for i, w in enumerate(words):
        raw = w[4].strip()
        # A: single-token search
        for label in _extract_sections_from_text(raw):
            cx = (w[0] + w[2]) / 2
            cy = (w[1] + w[3]) / 2
            found.append(dict(section=label, x=cx, y=cy,
                              x0=w[0], x1=w[2], y0=w[1], y1=w[3]))

        # B: sliding 2-token window (catches split labels)
        if i < len(words) - 1:
            nw = words[i + 1]
            combined = raw + nw[4].strip()
            for label in _extract_sections_from_text(combined):
                # Only add if this label wasn't already found from token A or B alone
                if not any(s['section'] == label and abs(s['x'] - (w[0]+w[2])/2) < 2
                           for s in found):
                    cx = (w[0] + w[2]) / 2
                    cy = (w[1] + w[3]) / 2
                    found.append(dict(section=label, x=cx, y=cy,
                                      x0=w[0], x1=w[2], y0=w[1], y1=w[3]))

    # Deduplicate on (section, approx_x, approx_y)
    seen_keys: set = set()
    unique = []
    for s in found:
        k = (s['section'], round(s['x'], 0), round(s['y'], 0))
        if k not in seen_keys:
            seen_keys.add(k)
            unique.append(s)
    return unique


def _sections_in_words_strict(words: List) -> List[Dict]:
    """
    Strict (fullmatch-based) section detection for use inside _extract_page.

    Only matches tokens that ARE section markers (e.g. '(BSCS-6B)', 'BSAI-2').
    Does NOT use finditer or a sliding window, so it never creates phantom
    section markers at wrong X positions from adjacent tokens.

    This is critical for correct rectangle splitting: the broad approach
    (finditer + 2-token window) generates ~3 entries per token at different
    X coordinates, causing the clustering algorithm to split cells that
    should remain whole, which loses lectures.
    """
    found = []
    for w in words:
        raw = w[4].strip()
        clean = re.sub(r'[()\uff08\uff09\s,]', '', raw).strip()
        if _SEC_PATTERN.fullmatch(raw) or _SEC_PATTERN.fullmatch(clean):
            norm = _norm_section(clean)
            cx = (w[0] + w[2]) / 2
            cy = (w[1] + w[3]) / 2
            found.append(dict(section=norm, x=cx, y=cy,
                              x0=w[0], x1=w[2], y0=w[1], y1=w[3]))
    seen_keys: set = set()
    unique = []
    for s in found:
        k = (s['section'], round(s['x'], 0), round(s['y'], 0))
        if k not in seen_keys:
            seen_keys.add(k)
            unique.append(s)
    return unique


def _sections_match(a: str, b: str) -> bool:
    return a == b


def _target_in_secs(secs: List[Dict], target: str) -> bool:
    norm_target = _norm_section(target)
    return any(_sections_match(s['section'], norm_target) for s in secs)


# ---------------------------------------------------------------------------
# Room / time helpers (new campus)
# ---------------------------------------------------------------------------

_DAY_OR_HEADER = re.compile(
    r'^(MONDAY|TUESDAY|WEDNESDAY|THURSDAY|FRIDAY|SATURDAY|SUNDAY|ROOM|TIME)$',
    re.IGNORECASE,
)
_ROOM_CONTINUERS = frozenset({
    'lab', 'hall', 'room', 'center', 'centre', 'studio',
})
# First glyph of a cell (e.g. "AI") often sits a few px left of the grid line.
_CELL_LEFT_SLOP = 8.0
# Room-row geometry. The latest RSCI timetable labels rows with bare numbers
# sitting one row apart; older formats keep a label's number within half a row
# of its head word. Clamped so a mis-detected row height cannot swamp the rule.
_ROOM_ROW_H_DEFAULT = 18.6
_ROOM_ROW_H_MIN = 12.0
_ROOM_ROW_H_MAX = 24.0
_TIME_TOKEN = re.compile(r'^\d{1,2}:\d{2}$')
_TIME_LABEL = re.compile(r'^(\d{1,2}):(\d{2})(?:\s*(AM|PM))?$', re.IGNORECASE)


def _is_room_label_word(w, xmax: float = 110.0) -> bool:
    """True if a PDF word sits in the left room column and is not a header."""
    text = w[4].strip()
    if not text or w[0] >= xmax or w[1] < 85:
        return False
    if _DAY_OR_HEADER.match(text):
        return False
    if text in ('►', '▼', '▶'):
        return False
    return True


def _starts_new_room_row(current: List, token,
                         row_h: float = _ROOM_ROW_H_DEFAULT) -> bool:
    """
    Decide whether `token` begins the next left-column room label.

    Words like 'Lab' continue the current label (they may sit on a wrapped
    second line). A new left-aligned title word starts a new row.

    A bare number is special: in the latest RSCI timetable the room labels ARE
    numbers ('210', '211', ...) with one label per row, so a number that sits
    about a row below the current label starts a new row. In the older formats
    a number is the tail of a label ('Classroom 1', 'Lab 2') and sits within
    half a row of its head word, so it continues the label.

    `row_h` is the measured row height; it keeps a default so callers outside
    _rooms() (scripts/tests) still work without measuring the page.
    """
    text = token[4].strip()
    y, x = token[1], token[0]
    first_y = current[0][1]
    last_y = current[-1][1]

    if re.fullmatch(r'\d{1,3}', text):
        return (y - last_y) >= row_h * 0.5
    if text.lower() in _ROOM_CONTINUERS:
        return False
    if y - first_y > 16:
        return True
    if x < 90 and y - last_y > 5:
        return True
    return y - last_y > 14


def _parse_hhmm_minutes(label: str) -> Optional[int]:
    """Parse '8:00', '8:00 AM', '1:30 PM' into minutes since midnight."""
    m = _TIME_LABEL.match((label or '').strip())
    if not m:
        return None
    h, mi = int(m.group(1)), int(m.group(2))
    ap = (m.group(3) or '').upper()
    if ap == 'PM' and h != 12:
        h += 12
    elif ap == 'AM' and h == 12:
        h = 0
    elif not ap and h < 7:
        h += 12
    return h * 60 + mi


def _format_hhmm(minutes: int, like: str) -> str:
    """Format minutes using the same AM/PM style as `like`."""
    minutes = minutes % (24 * 60)
    h, mi = divmod(minutes, 60)
    if re.search(r'\b(AM|PM)\b', like or '', re.I):
        ap = 'AM' if h < 12 else 'PM'
        h12 = h % 12
        if h12 == 0:
            h12 = 12
        return f"{h12}:{mi:02d} {ap}"
    return f"{h}:{mi:02d}"


def _add_slot_minutes(label: str, delta: int) -> str:
    base = _parse_hhmm_minutes(label)
    if base is None:
        return label
    return _format_hhmm(base + delta, label)


# ---------------------------------------------------------------------------
# Data class
# ---------------------------------------------------------------------------

@dataclass
class Lecture:
    day: str
    room: str
    start_time: str
    end_time: str
    course: str
    instructor: str
    section: str

    def to_dict(self) -> dict:
        return {
            "day": self.day,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "time": f"{self.start_time}-{self.end_time}",
            "course": self.course,
            "instructor": self.instructor,
            "room": self.room,
            "section": self.section,
        }


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class UniversalTimetableParser:
    DAYS = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday']

    def __init__(self, stream: bytes):
        """Load PDF entirely from an in-memory byte stream. No disk writes."""
        self.doc = fitz.open(stream=stream, filetype="pdf")

    # ------------------------------------------------------------------
    # Layout validation
    # ------------------------------------------------------------------

    def validate_layout(self) -> bool:
        """
        Check page 1 for the three required signals of the supported grid format:
          1. At least 3 time-column markers (HH:MM pattern, near top of page).
          2. At least 2 room labels in the left column.
          3. At least 1 section marker (BSCS/BSSE etc.) anywhere on the page.

        Returns True if all signals are found, False otherwise.
        """
        if len(self.doc) == 0:
            return False

        page = self.doc[0]
        words = page.get_text("words")

        time_count = sum(
            1 for w in words
            if w[1] < 110 and _TIME_TOKEN.match(w[4].strip())
        )
        room_count = len(self._rooms(page))
        section_count = len(_sections_in_words(words))

        ok = time_count >= 3 and room_count >= 2 and section_count >= 1
        if not ok:
            logger.info(
                "validate_layout FAILED: times=%d rooms=%d sections=%d",
                time_count, room_count, section_count,
            )
        return ok

    # ------------------------------------------------------------------
    # Section discovery
    # ------------------------------------------------------------------

    def get_all_sections(self) -> List[str]:
        """
        Scan ALL pages and return a sorted, deduplicated list of section labels
        dynamically detected from the PDF.

        Uses two complementary strategies per page:
          1. Per-token search (handles commas, mismatched parentheses).
          2. 2-token sliding window (handles split labels across tokens).

        NEVER hardcodes section names. Whatever labels exist in the
        uploaded PDF will be returned.
        """
        found: set = set()
        for page_num in range(len(self.doc)):  # scan ALL pages
            page = self.doc[page_num]
            words = page.get_text("words")
            for s in _sections_in_words(words):
                found.add(s['section'])
        return sorted(found)

    # ------------------------------------------------------------------
    # Parse all sections at once
    # ------------------------------------------------------------------

    def parse_all(self) -> Dict[str, List[dict]]:
        """
        Single-pass extraction: iterate through pages once and collect
        lectures for ALL sections simultaneously.

        This is dramatically faster than the previous approach which called
        _parse_section() for every detected section (O(sections × pages)).
        Now every page is processed exactly once (O(pages)).

        Returns {section: [slot_dicts]} for every section present in the PDF.
        """
        all_lectures: Dict[str, List[Lecture]] = defaultdict(list)

        for page_num in range(min(len(self.doc), 5)):
            page = self.doc[page_num]
            day = self.DAYS[page_num] if page_num < len(self.DAYS) else f"Day{page_num + 1}"

            rects = self._rectangles(page)
            slots = self._time_slots(page)
            rooms = self._rooms(page)
            time_keys = sorted(slots)

            processed: Dict[tuple, Dict] = {}
            for r in rects:
                k = (round(r['x0'], 1), round(r['y0'], 1),
                     round(r['x1'], 1), round(r['y1'], 1))
                if k not in processed:
                    processed[k] = r

            for rect in processed.values():
                words_all = self._words_in_rect(page, rect)
                all_secs = _sections_in_words_strict(words_all)

                if not all_secs:
                    continue

                if len(time_keys) > 1:
                    col_widths = [time_keys[i + 1] - time_keys[i]
                                  for i in range(len(time_keys) - 1)]
                    min_col_w = min(col_widths)
                else:
                    min_col_w = 40.0

                all_secs_sorted = sorted(all_secs, key=lambda s: s['x'])
                clusters: List[Dict] = []
                for s in all_secs_sorted:
                    if not clusters or s['x'] - clusters[-1]['x'] > min_col_w * 0.8:
                        clusters.append(s)

                n = len(clusters)
                if n == 1:
                    sub_rects = [rect]
                else:
                    sub_rects = self._split_rect(
                        rect, clusters, time_keys, words_all)

                for sub in sub_rects:
                    words_sub = self._words_in_rect(page, sub, x_margin=4)
                    secs_sub = _sections_in_words_strict(words_sub)

                    if not secs_sub:
                        continue

                    text = self._words_to_text(words_sub)
                    unique_targets = set(s['section'] for s in secs_sub)
                    unique_targets.update(_extract_sections_from_text(text))

                    room = self._room_for_rect(sub, rooms)
                    start, end = self._time_for_rect(sub, slots)

                    for target in unique_targets:
                        parsed = self._parse_cell(text, target)
                        if not parsed.get('course'):
                            continue

                        all_lectures[target].append(Lecture(
                            day=day,
                            room=room,
                            start_time=start,
                            end_time=end,
                            course=parsed['course'],
                            instructor=parsed.get('instructor', ''),
                            section=parsed.get('section') or target,
                        ))

        # Deduplicate and convert per section
        result: Dict[str, List[dict]] = {}
        for section, lectures in all_lectures.items():
            seen, unique = set(), []
            for lec in lectures:
                k = (lec.day, lec.course, lec.start_time, lec.end_time, lec.room)
                if k not in seen:
                    seen.add(k)
                    unique.append(lec)
            unique.sort(key=lambda l: (
                self.DAYS.index(l.day) if l.day in self.DAYS else 9,
                _parse_hhmm_minutes(l.start_time) or 0,
            ))
            result[section] = [lec.to_dict() for lec in unique]
            logger.info("parse_all: section=%s slots=%d", section, len(result[section]))

        return result

    # ------------------------------------------------------------------
    # Grid helpers (unchanged from Test/timetable_universal.py)
    # ------------------------------------------------------------------

    def _room_column_xmax(self, page, words=None) -> float:
        """Right edge of the room column, inferred from the first time header."""
        words = words if words is not None else page.get_text('words')
        time_xs = [
            w[0] for w in words
            if w[1] < 110 and _TIME_TOKEN.match(w[4].strip())
        ]
        if time_xs:
            return min(time_xs) - 1.5
        return 110.0

    def _row_height(self, page) -> float:
        """Median single-row height, or 30.0 when it cannot be measured.

        Callers that rely on the "one row" assumption clamp it themselves (see
        _rooms), so the raw value returned here is not guaranteed to be one row.
        """
        heights = []
        for d in page.get_drawings():
            r = d.get('rect')
            if r and r.x0 < 90 and 15 < r.height < 60:
                heights.append(r.height)
        if not heights:
            return 30.0
        heights.sort()
        return heights[len(heights) // 2]

    def _rectangles(self, page) -> List[Dict]:
        row_h = self._row_height(page)
        # Allow 2-row wrapped/merged cells (~2x row height) as well as
        # the original single-row filled cells.
        h_min, h_max = row_h * 0.5, row_h * 2.8
        seen, out = set(), []
        for d in page.get_drawings():
            r = d.get('rect')
            if not r:
                continue
            k = (round(r.x0, 1), round(r.y0, 1), round(r.x1, 1), round(r.y1, 1))
            if k in seen:
                continue
            seen.add(k)
            if 40 < r.width < 800 and h_min < r.height < h_max:
                out.append(dict(x0=r.x0, y0=r.y0, x1=r.x1, y1=r.y1,
                                width=r.width, height=r.height))
        # White / unfilled class cells have no fill rectangle — synthesise
        # them from section-marker text + vertical grid lines.
        for synth in self._synthetic_rects_for_unfilled(page, out):
            k = (round(synth['x0'], 1), round(synth['y0'], 1),
                 round(synth['x1'], 1), round(synth['y1'], 1))
            if k not in seen:
                seen.add(k)
                out.append(synth)
        return out

    def _vertical_grid_xs(self, page) -> List[float]:
        """X positions of thin vertical grid strokes in the timetable body."""
        xs: List[float] = []
        for d in page.get_drawings():
            r = d.get('rect')
            if not r:
                continue
            if r.width < 2.5 and r.height > 12 and r.x0 > 100:
                xs.append(r.x0)
        xs.sort()
        clustered: List[float] = []
        for x in xs:
            if not clustered or abs(x - clustered[-1]) > 3:
                clustered.append(x)
        return clustered

    def _row_cluster_around_section(self, words: List, sec: Dict,
                                     grid_xs: List[float] = None) -> List:
        """Words on the same row that belong to the same class as `sec`."""
        row = [
            w for w in words
            if w[0] > 105 and abs(((w[1] + w[3]) / 2) - sec['y']) < 10
        ]
        row.sort(key=lambda w: w[0])
        grid_xs = grid_xs or []
        clusters: List[List] = []
        current: List = []
        for w in row:
            crossed_grid = False
            if current and grid_xs:
                crossed_grid = any(
                    current[-1][2] < gx < w[0] for gx in grid_xs
                )
            if not current or (not crossed_grid and w[0] - current[-1][2] < 28):
                current.append(w)
            else:
                clusters.append(current)
                current = [w]
        if current:
            clusters.append(current)

        for cluster in clusters:
            for w in cluster:
                if w[0] <= sec['x'] <= w[2] and w[1] - 2 <= sec['y'] <= w[3] + 2:
                    return cluster
                if abs(((w[0] + w[2]) / 2) - sec['x']) < 4 and abs(((w[1] + w[3]) / 2) - sec['y']) < 4:
                    return cluster
        return []

    def _synthetic_rects_for_unfilled(self, page, existing: List[Dict]) -> List[Dict]:
        """
        Build cell rectangles for section markers that sit in unfilled
        (grid-line-only) cells. Filled cells are already in `existing`.
        """
        words = page.get_text('words')
        secs = _sections_in_words_strict(words)
        grid_xs = self._vertical_grid_xs(page)
        row_h = self._row_height(page)
        out: List[Dict] = []

        for s in secs:
            cx, cy = s['x'], s['y']
            if any(r['x0'] <= cx <= r['x1'] and r['y0'] <= cy <= r['y1']
                   for r in existing):
                continue

            cluster = self._row_cluster_around_section(words, s, grid_xs)
            if not cluster:
                continue

            x_min = min(w[0] for w in cluster)
            x_max = max(w[2] for w in cluster)
            lefts = [x for x in grid_xs if x <= x_min + 6]
            rights = [x for x in grid_xs if x >= x_max - 6]
            if not lefts or not rights:
                continue
            x0, x1 = max(lefts), min(rights)
            if x1 - x0 < 30:
                continue

            y0 = cy - row_h * 0.55
            y1 = cy + row_h * 0.55
            if any(abs(r['x0'] - x0) < 1 and abs(r['y0'] - y0) < 1
                   and abs(r['x1'] - x1) < 1 for r in out):
                continue
            out.append(dict(x0=x0, y0=y0, x1=x1, y1=y1,
                            width=x1 - x0, height=y1 - y0))
        return out

    def _time_slots(self, page) -> Dict[float, str]:
        words = page.get_text('words')
        time_words = []
        ampm_words = []
        for w in words:
            if w[1] >= 110:
                continue
            text = w[4].strip()
            if _TIME_TOKEN.match(text):
                time_words.append(w)
            elif text.upper() in ('AM', 'PM'):
                ampm_words.append(w)

        slots: Dict[float, str] = {}
        for w in time_words:
            label = w[4].strip()
            best, best_d = None, 25.0
            for a in ampm_words:
                if abs(a[1] - w[1]) < 12 and a[0] >= w[2] - 2:
                    d = a[0] - w[2]
                    if 0 <= d < best_d:
                        best_d = d
                        best = a[4].strip().upper()
            if best:
                label = f"{label} {best}"
            slots[w[0]] = label
        return dict(sorted(slots.items()))

    def _rooms(self, page) -> Dict[float, str]:
        """
        Reconstruct left-column room labels.

        Handles multi-token / wrapped names: 'Classroom 1',
        'Computer Lab 2', 'FYP Lab', 'Physics Lab'.
        """
        words = page.get_text('words')
        xmax = self._room_column_xmax(page, words)
        tokens = [w for w in words if _is_room_label_word(w, xmax)]
        tokens.sort(key=lambda w: (w[1], w[0]))
        if not tokens:
            return {}

        # Clamp so a mis-detected row height cannot swamp the numeric-label rule.
        row_h = min(max(self._row_height(page), _ROOM_ROW_H_MIN), _ROOM_ROW_H_MAX)
        rows: List[List] = []
        current = [tokens[0]]
        for t in tokens[1:]:
            if _starts_new_room_row(current, t, row_h):
                rows.append(current)
                current = [t]
            else:
                current.append(t)
        rows.append(current)

        rooms: Dict[float, str] = {}
        for row in rows:
            parts = [w[4].strip() for w in row]
            name = re.sub(r'\s+', ' ', ' '.join(parts)).strip()
            if not name:
                continue
            rooms[row[0][1]] = name
        return rooms

    def _words_in_rect(self, page, rect: Dict, x_margin: float = 0) -> List:
        x0, x1 = rect['x0'] + x_margin, rect['x1'] - x_margin
        # Never pull left-column room labels into a class cell.
        room_cut = min(x0, 111.0)
        out = []
        for w in page.get_text('words'):
            cy = (w[1] + w[3]) / 2
            if not (rect['y0'] <= cy <= rect['y1']):
                continue
            cx = (w[0] + w[2]) / 2
            if cx < room_cut:
                continue
            # Overlap test with left slop so the first word of a cell
            # (often starting just left of the grid line) is not clipped.
            if w[2] < x0 - _CELL_LEFT_SLOP or w[0] > x1:
                continue
            out.append(w)
        return out

    def _words_to_text(self, words: List) -> str:
        if not words:
            return ''
        sw = sorted(words, key=lambda w: (round(w[1] / 4) * 4, w[0]))
        lines, cur_line, cur_y = [], [], None
        for w in sw:
            if cur_y is None or abs(w[1] - cur_y) < 6:
                cur_line.append(w[4])
                cur_y = w[1]
            else:
                lines.append(' '.join(cur_line))
                cur_line, cur_y = [w[4]], w[1]
        if cur_line:
            lines.append(' '.join(cur_line))
        return '\n'.join(lines)

    # ------------------------------------------------------------------
    # Time / room snap
    # ------------------------------------------------------------------

    def _time_for_rect(self, rect: Dict, slots: Dict) -> Tuple[str, str]:
        if not slots:
            return 'Unknown', 'Unknown'
        keys = sorted(slots)
        sk = min(keys, key=lambda x: abs(x - rect['x0']))

        last = keys[-1]
        gap = keys[-1] - keys[-2] if len(keys) > 1 else 40.0
        # Infer 5:00 PM only when the cell occupies most of the last
        # (unlabelled) 4:30–5:00 column — not for classes that merely
        # touch the printed 4:30 PM header.
        if rect['x1'] - last > gap * 0.65:
            step = 30
            if len(keys) > 1:
                m0 = _parse_hhmm_minutes(slots[keys[0]])
                m1 = _parse_hhmm_minutes(slots[keys[1]])
                if m0 is not None and m1 is not None and m1 > m0:
                    step = m1 - m0
            return slots[sk], _add_slot_minutes(slots[last], step)

        ek = min(keys, key=lambda x: abs(x - rect['x1']))
        if ek <= sk:
            idx = keys.index(sk)
            ek = keys[idx + 1] if idx + 1 < len(keys) else sk
        return slots[sk], slots[ek]

    def _room_for_rect(self, rect: Dict, rooms: Dict) -> str:
        rect_mid_y = (rect['y0'] + rect['y1']) / 2
        in_span = []
        for ry, name in rooms.items():
            if rect['y0'] - 4 <= ry <= rect['y1'] + 4:
                in_span.append((abs(ry - rect_mid_y), name))
        if in_span:
            in_span.sort()
            return in_span[0][1]
        best, bd = None, float('inf')
        for ry, name in rooms.items():
            d = abs(ry - rect_mid_y)
            if d < bd:
                bd, best = d, name
        return best if bd < 25 else 'Unknown'

    # ------------------------------------------------------------------
    # Splitting
    # ------------------------------------------------------------------

    def _split_rect(self, rect: Dict, section_occs: List[Dict],
                    time_keys: List[float], all_words: List) -> List[Dict]:
        sorted_occs = sorted(section_occs, key=lambda o: o['x'])
        split_xs = []

        for i in range(1, len(sorted_occs)):
            left_x = sorted_occs[i - 1]['x']
            right_x = sorted_occs[i]['x']

            candidates = [tx for tx in time_keys if left_x < tx < right_x]
            if not candidates:
                candidates = [tx for tx in time_keys
                              if rect['x0'] < tx < rect['x1']]
            if not candidates:
                split_xs.append((left_x + right_x) / 2)
                continue

            best_tx, best_score = None, -float('inf')
            for tx in candidates:
                min_d = float('inf')
                for w in all_words:
                    wx0, wx1 = w[0], w[2]
                    if wx1 <= tx:
                        d = tx - wx1
                    elif wx0 >= tx:
                        d = wx0 - tx
                    else:
                        d = -abs(tx - (wx0 + wx1) / 2)
                    if d < min_d:
                        min_d = d
                if min_d > best_score:
                    best_score, best_tx = min_d, tx

            split_xs.append(best_tx if best_tx is not None
                            else (left_x + right_x) / 2)

        xs = [rect['x0']] + sorted(split_xs) + [rect['x1']]
        return [dict(x0=xs[k], y0=rect['y0'], x1=xs[k + 1], y1=rect['y1'],
                     width=xs[k + 1] - xs[k], height=rect['height'])
                for k in range(len(xs) - 1)]

    # ------------------------------------------------------------------
    # Text parser
    # ------------------------------------------------------------------

    def _parse_cell(self, text: str, target: str) -> Dict:
        """
        Parse a cell's text into {course, section, instructor}.

        Course is the text before the first section marker. Compound lists
        such as '(BSDS-5, BSCGV-4, BSCGV-5)' are recognised as one marker.
        """
        if not text.strip():
            return {}

        # First '(' that actually contains a section label — avoids a
        # stray opening paren becoming the split point.
        first_idx = None
        sec_blob = None
        for p in re.finditer(r'\(([^)]*)\)?', text):
            if _SEC_PATTERN.search(p.group(1) or ''):
                first_idx = p.start()
                sec_blob = p.group(1)
                break
        if first_idx is None:
            m = _SEC_PATTERN.search(text)
            if m:
                first_idx = m.start()
                sec_blob = m.group(0)

        if first_idx is None:
            course = re.sub(r'\s+', ' ', text).strip()
            return dict(course=course, section=target, instructor='')

        course = re.sub(r'\s+', ' ', text[:first_idx]).strip()
        instructor = re.sub(r'\s+', ' ', text[first_idx:]).strip()
        # Drop leftover section fragments that leaked from a neighbour cell
        course = re.sub(
            r'^(?:BSCS|BSSE|BSDS|BSIT|BSAI|BSCY|BSCGV|BSCOMP)'
            r'\s*[-\u2013]?\s*(?:\d+[A-Za-z]?)?,?\s*',
            '', course, flags=re.I,
        ).strip(' ,;()')
        instructor = re.sub(r'\s+', ' ', instructor)
        if sec_blob:
            instructor = re.sub(r'\(?' + re.escape(sec_blob) + r'\)?', '',
                                instructor).strip()
            instructor = re.sub(
                r'\(?(?:BSCS|BSSE|BSDS|BSIT|BSAI|BSCY|BSCGV|BSCOMP)'
                r'\s*[-\u2013]?\s*\d+\s*[A-Za-z]?,?\s*\)?',
                '', instructor, flags=re.I,
            ).strip(' ,;()')

        if not course or re.fullmatch(r'[(\s,.\-–]+', course):
            return {}

        if sec_blob and ',' in sec_blob:
            sections = [s.strip() for s in sec_blob.split(',') if s.strip()]
            norm_sections = [_norm_section(s) for s in sections]
            norm_target = _norm_section(target)
            final_section = norm_target if norm_target in norm_sections else (
                norm_sections[0] if norm_sections else target
            )
        else:
            final_section = _norm_section(sec_blob or target) or target

        return dict(course=course, section=final_section,
                    instructor=instructor)

    # ------------------------------------------------------------------
    # Per-page extraction (unchanged from Test/timetable_universal.py)
    # ------------------------------------------------------------------

    def _extract_page(self, page, day: str, target: str) -> List[Lecture]:
        norm_target = _norm_section(target)
        rects = self._rectangles(page)
        slots = self._time_slots(page)
        rooms = self._rooms(page)
        time_keys = sorted(slots)

        processed: Dict[tuple, Dict] = {}
        for r in rects:
            k = (round(r['x0'], 1), round(r['y0'], 1),
                 round(r['x1'], 1), round(r['y1'], 1))
            if k not in processed:
                processed[k] = r

        day_lectures: List[Lecture] = []

        for rect in processed.values():
            words_all = self._words_in_rect(page, rect)
            all_secs = _sections_in_words_strict(words_all)

            if not all_secs:
                continue

            if len(time_keys) > 1:
                col_widths = [time_keys[i+1] - time_keys[i]
                              for i in range(len(time_keys)-1)]
                min_col_w = min(col_widths)
            else:
                min_col_w = 40.0

            all_secs_sorted = sorted(all_secs, key=lambda s: s['x'])
            clusters: List[Dict] = []
            for s in all_secs_sorted:
                if not clusters or s['x'] - clusters[-1]['x'] > min_col_w * 0.8:
                    clusters.append(s)

            n = len(clusters)
            if n == 1:
                sub_rects = [rect]
            else:
                sub_rects = self._split_rect(
                    rect, clusters, time_keys, words_all)

            for sub in sub_rects:
                words_sub = self._words_in_rect(page, sub, x_margin=4)
                secs_sub = _sections_in_words_strict(words_sub)

                if not _target_in_secs(secs_sub, norm_target):
                    continue

                text = self._words_to_text(words_sub)
                parsed = self._parse_cell(text, target)
                if not parsed.get('course'):
                    continue

                room = self._room_for_rect(sub, rooms)
                start, end = self._time_for_rect(sub, slots)

                day_lectures.append(Lecture(
                    day=day,
                    room=room,
                    start_time=start,
                    end_time=end,
                    course=parsed['course'],
                    instructor=parsed.get('instructor', ''),
                    section=parsed.get('section') or target,
                ))

        # Deduplicate
        seen, unique = set(), []
        for lec in day_lectures:
            k = (lec.day, lec.course, lec.start_time, lec.end_time, lec.room)
            if k not in seen:
                seen.add(k)
                unique.append(lec)

        unique.sort(key=lambda l: _parse_hhmm_minutes(l.start_time) or 0)
        return unique

    # ------------------------------------------------------------------
    # Single-section parse (used internally by parse_all)
    # ------------------------------------------------------------------

    def _parse_section(self, target_class: str) -> List[Lecture]:
        lectures: List[Lecture] = []
        for page_num in range(min(len(self.doc), 5)):
            page = self.doc[page_num]
            day = self.DAYS[page_num]
            day_lecs = self._extract_page(page, day, target_class)
            lectures.extend(day_lecs)
        return lectures
