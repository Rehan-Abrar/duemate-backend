import os
import re
import sys
import fitz  # PyMuPDF
from pymongo import MongoClient
from dotenv import load_dotenv

# Ensure we can import from duemate-backend root if needed
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Load environment variables
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

def to_24h(time_str: str) -> str:
    if not time_str or time_str == "Unknown":
        return time_str
    try:
        h, m = map(int, time_str.split(":"))
        if h < 8: # 1, 2, 3, 4, 5, 6, 7 are PM
            h += 12
        return f"{h:02d}:{m:02d}"
    except Exception:
        return time_str

def detect_section(text: str) -> str:
    cleaned = re.sub(r'[\(（\)）]', '', text).strip().upper()
    match = re.match(r'^(BSCS|BSSE|BSDS|BSIT|BS\s*CS|BS\s*SE|BS\s*DS|BS\s*IT)\s*[-–]?\s*\d\s*[A-Z]$', cleaned, re.IGNORECASE)
    if match:
        norm = re.sub(r'\s+', '', cleaned)
        if '-' not in norm:
            m = re.match(r'^([A-Z]+)(\d[A-Z])$', norm)
            if m:
                norm = f"{m.group(1)}-{m.group(2)}"
        return norm
    return None

def extract_individual_sections(section_str: str) -> list:
    pattern = re.compile(
        r'\b(?:BSCS|BSSE|BSDS|BSIT|BS\s*CS|BS\s*SE|BS\s*DS|BS\s*IT)\s*[-–]?\s*\d\s*[A-Z]\b',
        re.IGNORECASE
    )
    sections = []
    for match in pattern.finditer(section_str):
        val = match.group(0).strip().upper()
        norm = re.sub(r'\s+', '', val)
        if '-' not in norm:
            m = re.match(r'^([A-Z]+)(\d[A-Z])$', norm)
            if m:
                norm = f"{m.group(1)}-{m.group(2)}"
        sections.append(norm)
    return sorted(list(set(sections)))

class TimetableParser:
    def __init__(self, pdf_path: str):
        self.pdf_path = pdf_path
        self.doc = fitz.open(pdf_path)
        self.days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']

    def get_all_rectangles(self, page) -> list:
        drawings = page.get_drawings()
        rectangles = []
        seen = set()
        for draw in drawings:
            rect = draw.get("rect")
            if rect:
                key = (
                    round(rect.x0, 1),
                    round(rect.y0, 1),
                    round(rect.x1, 1),
                    round(rect.y1, 1)
                )
                if key not in seen:
                    seen.add(key)
                    if 40 < rect.width < 700 and 10 < rect.height < 150:
                        rectangles.append({
                            'x0': rect.x0, 'y0': rect.y0, 'x1': rect.x1, 'y1': rect.y1,
                            'width': rect.width, 'height': rect.height
                        })
        return rectangles

    def get_rooms(self, page) -> dict:
        words = page.get_text("words")
        rooms = {}
        room_pattern = re.compile(r'^[A-Z]-\d{3}$|^B-\d{3}$|^Lab$|^Physics$|^Chemistry$')
        i = 0
        while i < len(words):
            w = words[i]
            x0, y0, text = w[0], w[1], w[4].strip()
            if x0 < 110 and room_pattern.match(text):
                if text in ('Lab', 'Physics', 'Chemistry') and i + 1 < len(words):
                    next_w = words[i + 1]
                    if abs(next_w[1] - y0) < 8:
                        rooms[y0] = f"{text} {next_w[4].strip()}"
                        i += 2
                        continue
                rooms[y0] = text
            i += 1
        return rooms

    def get_time_slots(self, page) -> dict:
        words = page.get_text("words")
        time_slots = {}
        time_pattern = re.compile(r'^(\d{1,2}):(\d{2})$')
        for w in words:
            x0, y0, text = w[0], w[1], w[4].strip()
            if y0 < 110 and time_pattern.match(text):
                time_slots[x0] = text
        return dict(sorted(time_slots.items()))

    def get_time_for_rect(self, rect: dict, time_slots: dict) -> tuple:
        if not time_slots:
            return "Unknown", "Unknown"
        time_keys = sorted(time_slots.keys())
        start_key = min(time_keys, key=lambda tx: abs(tx - rect['x0']))
        end_key = min(time_keys, key=lambda tx: abs(tx - rect['x1']))
        if end_key <= start_key:
            idx = time_keys.index(start_key)
            if idx + 1 < len(time_keys):
                end_key = time_keys[idx + 1]
            else:
                end_key = start_key
        return time_slots[start_key], time_slots[end_key]

    def get_room_for_rect(self, rect: dict, rooms: dict) -> str:
        rect_top = rect['y0']
        rect_center_y = (rect['y0'] + rect['y1']) / 2
        for room_y, room_name in rooms.items():
            if abs(room_y - rect_top) < 6:
                return room_name
        closest_room = None
        min_dist = float('inf')
        for room_y, room_name in rooms.items():
            dist = abs(room_y - rect_center_y)
            if dist < min_dist:
                min_dist = dist
                closest_room = room_name
        if min_dist < 35:
            return closest_room
        return "Unknown"

    def get_words_in_rect(self, page, rect: dict, x_margin: float = 0) -> list:
        words = page.get_text("words")
        result = []
        x0 = rect['x0'] + x_margin
        x1 = rect['x1'] - x_margin
        for w in words:
            wx0, wy0, wx1, wy1, text = w[0], w[1], w[2], w[3], w[4]
            cx = (wx0 + wx1) / 2
            cy = (wy0 + wy1) / 2
            if x0 <= cx <= x1 and rect['y0'] <= cy <= rect['y1']:
                result.append(w)
        return result

    def words_to_text(self, words: list) -> str:
        if not words:
            return ""
        sorted_words = sorted(words, key=lambda w: (round(w[1] / 4) * 4, w[0]))
        lines = []
        current_line = []
        current_y = None
        for w in sorted_words:
            y = w[1]
            if current_y is None or abs(y - current_y) < 6:
                current_line.append(w[4])
                current_y = y
            else:
                if current_line:
                    lines.append(' '.join(current_line))
                current_line = [w[4]]
                current_y = y
        if current_line:
            lines.append(' '.join(current_line))
        return '\n'.join(lines)

    def parse_lecture_text(self, text: str, target_class: str) -> dict:
        if not text.strip():
            return {'course': '', 'section': '', 'instructor': ''}
        section_paren = re.search(r'\(([^)]+)\)', text)
        plain_section = re.search(
            r'(BSCS|BSSE|BSDS|BSIT|BS\s*CS|BS\s*SE)\s*[-–]?\s*\d\s*[A-D]',
            text, re.IGNORECASE
        )
        if section_paren:
            section = section_paren.group(1).strip()
            idx = text.find(section_paren.group(0))
            course = text[:idx].strip().replace('\n', ' ')
            instructor = text[idx + len(section_paren.group(0)):].strip().replace('\n', ' ')
        elif plain_section:
            section = plain_section.group(0).strip()
            idx = text.find(section)
            course = text[:idx].strip().replace('\n', ' ')
            instructor = text[idx + len(section):].strip().replace('\n', ' ')
        else:
            return {
                'course': text.strip().replace('\n', ' '),
                'section': target_class,
                'instructor': ''
            }
        course = re.sub(r'\s+', ' ', course).strip()
        instructor = re.sub(r'\s+', ' ', instructor).strip()
        instructor = re.sub(
            r'\(?' + re.escape(section) + r'\)?', '', instructor
        ).strip()
        return {'course': course, 'section': section, 'instructor': instructor}

    def find_containing_rectangle(self, rectangles: list, x: float, y: float) -> dict:
        containing = [r for r in rectangles if r['x0'] <= x <= r['x1'] and r['y0'] <= y <= r['y1']]
        if not containing:
            return None
        return min(containing, key=lambda r: r['width'] * r['height'])

    def split_rect_by_timeslots(self, rect: dict, occurrences: list, time_keys: list, words_in_rect: list) -> list:
        sorted_occs = sorted(occurrences, key=lambda o: o['x'])
        split_xs = []
        for i in range(1, len(sorted_occs)):
            left_occ = sorted_occs[i - 1]
            right_occ = sorted_occs[i]
            candidates = [tx for tx in time_keys if left_occ['x'] < tx < right_occ['x']]
            if not candidates:
                candidates = [tx for tx in time_keys if rect['x0'] < tx < rect['x1']]
                if not candidates:
                    split_xs.append((left_occ['x'] + right_occ['x']) / 2)
                    continue
            best_tx = None
            max_min_dist = -float('inf')
            for tx in candidates:
                min_dist = float('inf')
                for w in words_in_rect:
                    wx0, wx1 = w[0], w[2]
                    if any(target in w[4] for target in ["BSCS", "BSSE", "BSDS", "BSIT", "6B"]):
                        continue
                    if wx1 <= tx:
                        dist = tx - wx1
                    elif wx0 >= tx:
                        dist = wx0 - tx
                    else:
                        dist = -abs(tx - (wx0 + wx1)/2)
                    if dist < min_dist:
                        min_dist = dist
                if min_dist > max_min_dist:
                    max_min_dist = min_dist
                    best_tx = tx
            split_xs.append(best_tx if best_tx is not None else (left_occ['x'] + right_occ['x']) / 2)
        x_coords = [rect['x0']] + sorted(split_xs) + [rect['x1']]
        sub_rects = []
        for k in range(len(x_coords) - 1):
            x0 = x_coords[k]
            x1 = x_coords[k + 1]
            sub_rects.append({
                'x0': x0, 'y0': rect['y0'], 'x1': x1, 'y1': rect['y1'],
                'width': x1 - x0, 'height': rect['height']
            })
        return sub_rects

    def extract_all_lectures(self) -> list:
        all_lectures = []
        for page_num in range(min(len(self.doc), 5)):
            page = self.doc[page_num]
            day = self.days[page_num]
            all_rectangles = self.get_all_rectangles(page)
            rooms = self.get_rooms(page)
            time_slots = self.get_time_slots(page)
            time_keys = sorted(time_slots.keys())

            all_words = page.get_text("words")
            target_occ = []
            for w in all_words:
                text = w[4].strip()
                sec = detect_section(text)
                if sec:
                    cx = (w[0] + w[2]) / 2
                    cy = (w[1] + w[3]) / 2
                    target_occ.append({
                        'text': text, 'section': sec, 'x': cx, 'y': cy,
                        'x0': w[0], 'x1': w[2], 'y0': w[1], 'y1': w[3]
                    })

            rect_groups = defaultdict(list)
            for occ in target_occ:
                rect = self.find_containing_rectangle(all_rectangles, occ['x'], occ['y'])
                if rect is None:
                    continue
                key = (round(rect['x0'], 1), round(rect['y0'], 1), round(rect['x1'], 1), round(rect['y1'], 1))
                rect_groups[key].append((occ, rect))

            day_lectures = []
            for key, occ_rect_list in rect_groups.items():
                rect = occ_rect_list[0][1]
                occs = [item[0] for item in occ_rect_list]

                if len(occs) == 1:
                    sub_rects = [rect]
                else:
                    words_in_main = self.get_words_in_rect(page, rect)
                    sub_rects = self.split_rect_by_timeslots(rect, occs, time_keys, words_in_main)

                for sub_rect in sub_rects:
                    MARGIN = 4
                    words_in = self.get_words_in_rect(page, sub_rect, x_margin=MARGIN)
                    cell_text = self.words_to_text(words_in)
                    if not cell_text.strip():
                        continue

                    sub_occ = None
                    for occ in occs:
                        if sub_rect['x0'] <= occ['x'] <= sub_rect['x1'] and sub_rect['y0'] <= occ['y'] <= sub_rect['y1']:
                            sub_occ = occ
                            break
                    if not sub_occ:
                        sub_occ = min(occs, key=lambda o: abs(o['x'] - (sub_rect['x0'] + sub_rect['x1'])/2))

                    target_class = sub_occ['section']
                    parsed = self.parse_lecture_text(cell_text, target_class)
                    if not parsed['course']:
                        continue

                    room = self.get_room_for_rect(sub_rect, rooms)
                    start_time, end_time = self.get_time_for_rect(sub_rect, time_slots)

                    parsed_section_str = parsed['section'] or target_class
                    individual_secs = extract_individual_sections(parsed_section_str)
                    if not individual_secs:
                        individual_secs = [target_class]
                        
                    for sec in individual_secs:
                        # Normalize instructors list if slashed
                        instructors_raw = parsed['instructor']
                        if '/' in instructors_raw:
                            instructors = [i.strip() for i in instructors_raw.split('/') if i.strip()]
                        else:
                            instructors = instructors_raw.strip()

                        day_lectures.append({
                            'day': day,
                            'room': room,
                            'start_time': to_24h(start_time),
                            'end_time': to_24h(end_time),
                            'time': f"{to_24h(start_time)}-{to_24h(end_time)}",
                            'course': parsed['course'],
                            'instructor': instructors,
                            'section': sec
                        })

            seen = set()
            for lec in day_lectures:
                key = (lec['course'], lec['start_time'], lec['room'], lec['section'])
                if key not in seen:
                    seen.add(key)
                    all_lectures.append(lec)

        return all_lectures

def main():
    pdf_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'Test', 'Timetable.pdf'))
    if not os.path.exists(pdf_path):
        print(f"Error: Timetable PDF not found at {pdf_path}")
        return
        
    print("📖 Parsing Timetable PDF...")
    parser = TimetableParser(pdf_path)
    lectures = parser.extract_all_lectures()
    print(f"✅ Extracted {len(lectures)} lectures across all classes.")

    mongo_uri = os.getenv("MONGODB_URI")
    if not mongo_uri:
        print("Error: MONGODB_URI environment variable not configured.")
        return

    print("🔌 Connecting to MongoDB...")
    client = MongoClient(mongo_uri)
    db = client.get_database("duemate")
    
    print("🧹 Cleaning existing 'timetable_slots' collection...")
    db.timetable_slots.delete_many({})
    
    print("📥 Inserting new lectures into 'timetable_slots'...")
    if lectures:
        # Create indexes
        db.timetable_slots.create_index([("section", 1), ("day", 1)])
        db.timetable_slots.create_index("section")
        
        db.timetable_slots.insert_many(lectures)
        print(f"🎉 Successfully inserted {len(lectures)} timetable slots into MongoDB!")
    else:
        print("⚠️ No lectures found to insert.")

if __name__ == "__main__":
    main()
