"""
Universal Timetable Parser — Backend Edition
=============================================
Ported from Test/timetable_universal.py with the following additions:
  - Stream-based (in-memory) loading: no temp files on disk.
  - Layout validation: rejects PDFs that are not the supported grid format.
  - parse_all(): extracts slots for EVERY section found in the PDF.
  - get_all_sections(): returns the sorted list of detected section labels.

Supported format: Riphah University grid-format timetables only.
  - Each page = one weekday (Mon–Fri).
  - Left column: room labels (e.g. A-317, Lab 2).
  - Top row: time columns (HH:MM pattern, y < 110).
  - Cells: section markers (BSCS-6B etc.) + course + instructor text.
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


def _sections_match(a: str, b: str) -> bool:
    return a == b


def _target_in_secs(secs: List[Dict], target: str) -> bool:
    norm_target = _norm_section(target)
    return any(_sections_match(s['section'], norm_target) for s in secs)


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

        time_pat = re.compile(r'^\d{1,2}:\d{2}$')
        room_pat = re.compile(r'^[A-Z]-\d{3}$|^B-\d{3}$|^Lab$|^Physics$|^Chemistry$')

        time_count = sum(
            1 for w in words
            if w[1] < 110 and time_pat.match(w[4].strip())
        )
        room_count = sum(
            1 for w in words
            if w[0] < 110 and room_pat.match(w[4].strip())
        )
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
        Returns {section: [slot_dicts]} for every section present in the PDF.
        Each slot dict: {day, start_time, end_time, time, course, instructor, room, section}
        """
        sections = self.get_all_sections()
        result: Dict[str, List[dict]] = {}
        for section in sections:
            lectures = self._parse_section(section)
            result[section] = [lec.to_dict() for lec in lectures]
            logger.info("parse_all: section=%s slots=%d", section, len(result[section]))
        return result

    # ------------------------------------------------------------------
    # Grid helpers (unchanged from Test/timetable_universal.py)
    # ------------------------------------------------------------------

    def _row_height(self, page) -> float:
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
        h_min, h_max = row_h * 0.5, row_h * 1.6
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
        return out

    def _time_slots(self, page) -> Dict[float, str]:
        pat = re.compile(r'^\d{1,2}:\d{2}$')
        slots = {}
        for w in page.get_text('words'):
            if w[1] < 110 and pat.match(w[4].strip()):
                slots[w[0]] = w[4].strip()
        return dict(sorted(slots.items()))

    def _rooms(self, page) -> Dict[float, str]:
        pat = re.compile(r'^[A-Z]-\d{3}$|^B-\d{3}$|^Lab$|^Physics$|^Chemistry$')
        words = page.get_text('words')
        rooms = {}
        i = 0
        while i < len(words):
            w = words[i]
            x0, y0, text = w[0], w[1], w[4].strip()
            if x0 < 110 and pat.match(text):
                if text in ('Lab', 'Physics', 'Chemistry') and i + 1 < len(words):
                    nw = words[i + 1]
                    if abs(nw[1] - y0) < 8:
                        rooms[y0] = f"{text} {nw[4].strip()}"
                        i += 2
                        continue
                rooms[y0] = text
            i += 1
        return rooms

    def _words_in_rect(self, page, rect: Dict, x_margin: float = 0) -> List:
        x0, x1 = rect['x0'] + x_margin, rect['x1'] - x_margin
        out = []
        for w in page.get_text('words'):
            cx = (w[0] + w[2]) / 2
            cy = (w[1] + w[3]) / 2
            if x0 <= cx <= x1 and rect['y0'] <= cy <= rect['y1']:
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
        ek = min(keys, key=lambda x: abs(x - rect['x1']))
        if ek <= sk:
            idx = keys.index(sk)
            ek = keys[idx + 1] if idx + 1 < len(keys) else sk
        return slots[sk], slots[ek]

    def _room_for_rect(self, rect: Dict, rooms: Dict) -> str:
        rect_mid_y = (rect['y0'] + rect['y1']) / 2
        for ry, name in rooms.items():
            if rect['y0'] - 4 <= ry <= rect['y1'] + 4:
                return name
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
        Handles:
          - '(BSCS-6B)' parenthesised section markers
          - 'BSCS-7' section markers without a trailing letter
          - Multiple sections in one cell (uses target to pick the right one)
        """
        if not text.strip():
            return {}

        # Try to find a parenthesised section label first
        sec_paren = re.search(r'\(([^)]+)\)', text)

        # Broader plain-text section search (handles no-letter variants like BSCS-7)
        sec_plain = re.search(
            r'(BSCS|BSSE|BSDS|BSIT|BSAI|BSCY|BSCGV|BSComp|BSCOMP)'
            r'\s*[-\u2013]?\s*\d+\s*[A-Za-z]?',
            text, re.IGNORECASE,
        )

        if sec_paren:
            sec = sec_paren.group(1).strip()
            idx = text.find(sec_paren.group(0))
            course = text[:idx].strip().replace('\n', ' ')
            instructor = text[idx + len(sec_paren.group(0)):].strip().replace('\n', ' ')
        elif sec_plain:
            sec = sec_plain.group(0).strip()
            idx = text.find(sec)
            course = text[:idx].strip().replace('\n', ' ')
            instructor = text[idx + len(sec):].strip().replace('\n', ' ')
        else:
            return dict(course=text.strip().replace('\n', ' '),
                        section=target, instructor='')

        course = re.sub(r'\s+', ' ', course).strip()
        instructor = re.sub(r'\s+', ' ', instructor).strip()
        instructor = re.sub(r'\(?' + re.escape(sec) + r'\)?', '',
                            instructor).strip()
        return dict(course=course, section=_norm_section(sec) or sec,
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
            all_secs = _sections_in_words(words_all)

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
                secs_sub = _sections_in_words(words_sub)

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
            k = (lec.course, lec.start_time, lec.room)
            if k not in seen:
                seen.add(k)
                unique.append(lec)

        unique.sort(key=lambda l: (
            int(l.start_time.split(':')[0]) * 60 + int(l.start_time.split(':')[1])
            if ':' in l.start_time else 0))
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
