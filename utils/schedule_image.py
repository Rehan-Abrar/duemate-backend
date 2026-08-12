"""
DueMate — Schedule Image Generator
Generates a compact portrait timetable PNG from stored timetable data.

Used by the GET /api/student/timetable/image endpoint.
"""

import io
import os
from typing import List, Dict

from PIL import Image, ImageDraw, ImageFont

# ── Font paths ──────────────────────────────────────────────────────────────
_FONT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fonts")
_F_REGULAR = os.path.join(_FONT_DIR, "Inter-Regular.ttf")
_F_MEDIUM = os.path.join(_FONT_DIR, "Inter-Medium.ttf")
_F_SEMIBOLD = os.path.join(_FONT_DIR, "Inter-SemiBold.ttf")
_F_BOLD = os.path.join(_FONT_DIR, "Inter-Bold.ttf")

# ── Color palette (dark theme) ──────────────────────────────────────────────
_BG = (13, 14, 20)
_SURFACE = (22, 24, 35)
_SURFACE2 = (26, 29, 42)
_BORDER = (42, 46, 68)
_TEXT_PRI = (240, 242, 255)
_TEXT_META = (148, 154, 184)
_TEXT_MUT = (72, 77, 108)

_DAY_ACCENTS = {
    "Monday": (91, 138, 240),
    "Tuesday": (155, 110, 245),
    "Wednesday": (61, 191, 168),
    "Thursday": (240, 122, 91),
    "Friday": (240, 191, 58),
    "Saturday": (180, 140, 220),
}

_DAY_ORDER = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]

_WIDTH = 1080


# ── Helpers ─────────────────────────────────────────────────────────────────

def _load_font(path, size):
    try:
        return ImageFont.truetype(path, size)
    except Exception:
        return ImageFont.load_default()


def _rounded_rect(draw, xy, r, fill, outline=None, ow=0):
    draw.rounded_rectangle(xy, radius=r, fill=fill,
                           outline=outline, width=ow if outline else 0)


def _word_wrap(draw, text, font, max_w):
    words, lines, cur = text.split(), [], ""
    for w in words:
        t = (cur + " " + w).strip()
        if draw.textlength(t, font=font) <= max_w:
            cur = t
        else:
            if cur:
                lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines or [text]


def _line_height(font, n=1, leading=5):
    b = font.getbbox("Ay")
    return (b[3] - b[1]) * n + leading * (n - 1)


def _draw_text_lines(draw, lines, x, y, font, fill, leading=5):
    b = font.getbbox("Ay")
    step = b[3] - b[1] + leading
    for l in lines:
        draw.text((x, y), l, font=font, fill=fill)
        y += step
    return y


def _format_time_display(time_str):
    if not time_str:
        return ""
    parts = time_str.split(":")
    if len(parts) != 2:
        return time_str
    try:
        h = int(parts[0])
        m = int(parts[1])
        if h == 0:
            return f"12:{m:02d}"
        elif h < 12:
            return f"{h}:{m:02d}"
        elif h == 12:
            return f"12:{m:02d}"
        else:
            return f"{h - 12}:{m:02d}"
    except (ValueError, IndexError):
        return time_str


# ── Main renderer ───────────────────────────────────────────────────────────

def render_schedule_image(slots: List[dict], section_name: str) -> bytes:
    """
    Render a timetable schedule as a PNG image.

    Args:
        slots: list of slot dicts from the user_timetables document,
               each with keys: day, start_time, end_time, course, room, instructor
        section_name: e.g. "BSCS-6B"

    Returns:
        PNG image bytes
    """
    # Group slots by day
    by_day: Dict[str, list] = {}
    for slot in slots:
        day = slot.get("day", "")
        by_day.setdefault(day, []).append(slot)

    schedule = []
    for day in _DAY_ORDER:
        day_slots = by_day.get(day, [])
        if day_slots:
            classes = []
            for s in day_slots:
                start = s.get("start_time", "")
                end = s.get("end_time", "")
                if not start and "time" in s:
                    parts = s["time"].split("-")
                    start = parts[0].strip() if parts else ""
                    end = parts[1].strip() if len(parts) > 1 else ""
                time_range = f"{_format_time_display(start)} - {_format_time_display(end)}"
                course = s.get("course", "Unknown Course")
                room = s.get("room", "")
                classes.append({
                    "time": time_range,
                    "course": course,
                    "room": room,
                })
            schedule.append({"day": day, "classes": classes})

    if not schedule:
        return _render_empty_image(section_name)

    # ── Fonts ───────────────────────────────────────────────────────────
    fonts = {
        "app": _load_font(_F_BOLD, 54),
        "sub": _load_font(_F_MEDIUM, 25),
        "day": _load_font(_F_BOLD, 29),
        "course": _load_font(_F_BOLD, 30),
        "meta": _load_font(_F_SEMIBOLD, 24),
        "footer": _load_font(_F_REGULAR, 21),
    }

    MARGIN = 44
    INNER_W = _WIDTH - MARGIN * 2
    ACCENT_BAR = 4
    TEXT_INDENT = ACCENT_BAR + 16
    MAX_TEXT_W = INNER_W - TEXT_INDENT - 16
    HEADER_H = 118
    FOOTER_H = 58
    DAY_HDR_H = 46
    CARD_PAD_V = 16
    CARD_GAP = 6
    DAY_GAP = 36
    SECTION_PAD = 8

    # ── Measure content height ──────────────────────────────────────────
    dummy = Image.new("RGB", (_WIDTH, 100), _BG)
    dd = ImageDraw.Draw(dummy)

    def card_h(cls):
        course_lines = _word_wrap(dd, cls["course"], fonts["course"], MAX_TEXT_W)
        return (CARD_PAD_V + _line_height(fonts["meta"]) + 7
                + _line_height(fonts["course"], len(course_lines)) + CARD_PAD_V)

    content_h = 0
    for d in schedule:
        content_h += DAY_HDR_H + SECTION_PAD
        for i, c in enumerate(d["classes"]):
            content_h += card_h(c)
            if i < len(d["classes"]) - 1:
                content_h += CARD_GAP
        content_h += DAY_GAP

    total_h = HEADER_H + content_h + FOOTER_H + 16

    # ── Create canvas ───────────────────────────────────────────────────
    img = Image.new("RGB", (_WIDTH, total_h), _BG)
    draw = ImageDraw.Draw(img)

    # Dot-grid texture
    for gy in range(18, total_h, 34):
        for gx in range(18, _WIDTH, 34):
            draw.point((gx, gy), fill=(255, 255, 255, 14))

    # ── HEADER ──────────────────────────────────────────────────────────
    draw.text((MARGIN, 36), "DueMate", font=fonts["app"], fill=_TEXT_PRI)
    nx = MARGIN + int(draw.textlength("DueMate", font=fonts["app"])) + 9
    draw.ellipse([nx, 36 + 36, nx + 9, 36 + 45], fill=(91, 138, 240))
    draw.text((MARGIN, 98), f"{section_name}  -  Weekly Schedule",
              font=fonts["sub"], fill=_TEXT_META)
    draw.line([(MARGIN, HEADER_H - 2), (_WIDTH - MARGIN, HEADER_H - 2)],
              fill=_BORDER, width=1)

    y = HEADER_H + 12

    # ── DAY SECTIONS ────────────────────────────────────────────────────
    for di, day_data in enumerate(schedule):
        day_name = day_data["day"]
        accent = _DAY_ACCENTS.get(day_name, (150, 150, 200))
        dim_a = tuple(int(c * 0.28) for c in accent)
        tint = tuple(int(_BG[i] + (accent[i] - _BG[i]) * 0.10) for i in range(3))

        # Day header bar
        _rounded_rect(draw, [MARGIN, y, MARGIN + INNER_W, y + DAY_HDR_H],
                      r=9, fill=tint)
        _rounded_rect(draw, [MARGIN, y, MARGIN + ACCENT_BAR, y + DAY_HDR_H],
                      r=3, fill=accent)
        label_y = y + (DAY_HDR_H - _line_height(fonts["day"])) // 2
        draw.text((MARGIN + TEXT_INDENT, label_y), day_name.upper(),
                  font=fonts["day"], fill=accent)

        # Class count badge
        badge = str(len(day_data["classes"]))
        bw = int(draw.textlength(badge, font=fonts["meta"])) + 20
        bx = MARGIN + INNER_W - bw - 10
        by = y + (DAY_HDR_H - 28) // 2
        _rounded_rect(draw, [bx, by, bx + bw, by + 28], r=14, fill=dim_a)
        draw.text((bx + 10, by + 4), badge, font=fonts["meta"], fill=accent)

        y += DAY_HDR_H + SECTION_PAD

        # Class cards
        for ci, cls in enumerate(day_data["classes"]):
            ch = card_h(cls)
            card_fill = _SURFACE if ci % 2 == 0 else _SURFACE2
            _rounded_rect(draw, [MARGIN, y, MARGIN + INNER_W, y + ch],
                          r=9, fill=card_fill, outline=_BORDER, ow=1)
            _rounded_rect(draw, [MARGIN, y, MARGIN + ACCENT_BAR, y + ch],
                          r=3, fill=accent)

            tx = MARGIN + TEXT_INDENT
            ty = y + CARD_PAD_V

            # Meta line: time + room
            meta = f"{cls['time']}  -  {cls['room']}" if cls['room'] else cls['time']
            draw.text((tx, ty), meta, font=fonts["meta"], fill=accent)
            ty += _line_height(fonts["meta"]) + 7

            # Course name
            course_lines = _word_wrap(draw, cls["course"], fonts["course"], MAX_TEXT_W)
            _draw_text_lines(draw, course_lines, tx, ty, fonts["course"], _TEXT_PRI)

            y += ch + CARD_GAP

        # Divider between days
        if di < len(schedule) - 1:
            div_y = y + DAY_GAP // 2
            draw.line([(MARGIN + 16, div_y), (_WIDTH - MARGIN - 16, div_y)],
                      fill=_BORDER, width=1)

        y += DAY_GAP

    # ── FOOTER ──────────────────────────────────────────────────────────
    draw.line([(MARGIN, y), (_WIDTH - MARGIN, y)], fill=_BORDER, width=1)
    ft = "Generated by DueMate  -  Your academic companion"
    fw = int(draw.textlength(ft, font=fonts["footer"]))
    draw.text(((_WIDTH - fw) // 2, y + 16), ft, font=fonts["footer"], fill=_TEXT_MUT)

    # ── Encode to PNG bytes ─────────────────────────────────────────────
    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    buf.seek(0)
    return buf.getvalue()


def _render_empty_image(section_name: str) -> bytes:
    """Render a minimal 'no classes' image when the timetable is empty."""
    img = Image.new("RGB", (_WIDTH, 320), _BG)
    draw = ImageDraw.Draw(img)

    font_app = _load_font(_F_BOLD, 54)
    font_sub = _load_font(_F_MEDIUM, 25)
    font_empty = _load_font(_F_REGULAR, 28)

    MARGIN = 44

    draw.text((MARGIN, 36), "DueMate", font=font_app, fill=_TEXT_PRI)
    nx = MARGIN + int(draw.textlength("DueMate", font=font_app)) + 9
    draw.ellipse([nx, 36 + 36, nx + 9, 36 + 45], fill=(91, 138, 240))
    draw.text((MARGIN, 98), f"{section_name}  -  Weekly Schedule",
              font=font_sub, fill=_TEXT_META)

    draw.text((MARGIN, 180), "No classes scheduled.",
              font=font_empty, fill=_TEXT_MUT)

    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    buf.seek(0)
    return buf.getvalue()
