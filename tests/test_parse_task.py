import os
import sys
from datetime import datetime, timezone
import json
import pytest
from dotenv import load_dotenv

load_dotenv()

TEST_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "duemate-backend"))
if TEST_ROOT not in sys.path:
    sys.path.insert(0, TEST_ROOT)

from utils.parse_task import (
    _normalize_due_date,
    _extract_json_from_response,
    _extract_deterministic_fields,
    detect_course,
    detect_due_date,
    extract_title,
    parse_task,
)

ASSIGNMENT_MSG = (
    "Here is complete assignment 4, student need to submit on 22 June 2026 before 2PM in my office"
)
FIXED_NOW = datetime(2026, 6, 12, 12, 0, tzinfo=timezone.utc)


class TestDateParsing:
    def test_normalize_due_date_clears_default_jan_1(self):
        assert _normalize_due_date("0001-01-01T00:00:00Z") is None
        assert _normalize_due_date("1970-01-01T00:00:00Z") is None
        assert _normalize_due_date("2026-01-01T00:00:00Z", ASSIGNMENT_MSG, FIXED_NOW) is None

    def test_normalize_due_date_valid(self):
        dt = _normalize_due_date("2026-06-22T14:00:00Z", ASSIGNMENT_MSG, FIXED_NOW)
        assert dt is not None
        assert dt.year == 2026
        assert dt.month == 6
        assert dt.day == 22
        assert dt.hour == 14


class TestStructuredValidation:
    def test_json_extraction_handles_fences(self):
        raw = "```json\n{\"task\": \"test\", \"confidence\": 0.9}\n```"
        assert _extract_json_from_response(raw) == {"task": "test", "confidence": 0.9}

    def test_invalid_json_raises(self):
        with pytest.raises(json.JSONDecodeError):
            _extract_json_from_response("This is just text.")


class TestDeterministicExtraction:
    def test_assignment_message_course_not_on22(self):
        normalized = ASSIGNMENT_MSG
        assert detect_course(normalized) is None

    def test_assignment_message_due_date(self):
        due = detect_due_date(ASSIGNMENT_MSG, FIXED_NOW)
        assert due is not None
        assert due.year == 2026
        assert due.month == 6
        assert due.day == 22
        assert due.hour == 14

    def test_assignment_message_title(self):
        title = extract_title(ASSIGNMENT_MSG, "assignment", None)
        assert title == "Assignment 4"

    def test_deterministic_fields_bundle(self):
        fields = _extract_deterministic_fields(ASSIGNMENT_MSG, now=FIXED_NOW)
        assert fields["task_type"] == "assignment"
        assert fields["course"] is None
        assert fields["title"] == "Assignment 4"
        assert fields["due_date"] is not None
        assert fields["due_date"].day == 22


class TestParseTaskIntegration:
    def test_parse_task_assignment_message_without_groq(self, monkeypatch):
        monkeypatch.delenv("GROQ_API_KEY", raising=False)

        result = parse_task(ASSIGNMENT_MSG)
        assert result["task_type"] == "assignment"
        assert result["title"] == "Assignment 4"
        assert result["course"] is None
        assert result["due_date"] is not None
        assert result["due_date"].month == 6
        assert result["due_date"].day == 22
        assert result["due_date"].hour == 14
        assert result["parse_method"] == "regex_fallback"
        assert result["needs_review"] is False

class TestRealWorldStudentMessages:
    def test_pdc_assignment_hinglish(self):
        # "PDC assignment submit karna hai friday tak"
        result = parse_task("PDC assignment submit karna hai friday tak")
        assert result["task_type"] == "assignment"
        assert result["course"] == "Parallel & Distributed Computing"
        assert result["due_date"] is not None
        # Should be a Friday
        assert result["due_date"].weekday() == 4 # Friday
        assert result["needs_review"] is False

    def test_toa_quiz_hinglish(self):
        # "kal TOA ka quiz hai chapter 3 aur 4 se"
        result = parse_task("kal TOA ka quiz hai chapter 3 aur 4 se")
        assert result["task_type"] == "quiz"
        assert result["course"] == "Theory of Automata"
        assert result["quiz_material"] is not None
        assert "3" in result["quiz_material"]
        assert "4" in result["quiz_material"]
        assert result["due_date"] is not None

    def test_cn_project_urdu(self):
        # "guys cn ka project 30 June 2026 tak jama karwana hai please note karlo"
        result = parse_task("guys cn ka project 30 June 2026 tak jama karwana hai please note karlo")
        assert result["task_type"] == "assignment"
        assert result["course"] == "Computer Networks"
        assert result["due_date"] is not None
        assert result["due_date"].year == 2026
        assert result["due_date"].month == 6
        assert result["due_date"].day == 30

    def test_ai_class_quiz_informal(self):
        # "Sir said next week AI class quiz related to neural networks and backprop"
        result = parse_task("Sir said next week AI class quiz related to neural networks and backprop")
        assert result["task_type"] == "quiz"
        assert result["course"] == "AI-Driven Software Development"
        assert result["due_date"] is None
        assert result["needs_review"] is True

    def test_adbms_assignment(self):
        # "Advanced DBMS assignment 3 due on 12 July 2026"
        result = parse_task("Advanced DBMS assignment 3 due on 12 July 2026")
        assert result["task_type"] == "assignment"
        assert result["course"] == "Advanced DBMS"
        assert result["due_date"] is not None
        assert result["due_date"].year == 2026
        assert result["due_date"].month == 7
        assert result["due_date"].day == 12
        assert "3" in result["title"]


class TestTimeParsing:
    """Verify explicit times in messages override defaults."""

    def test_time_range_2_to_5pm(self):
        result = parse_task("Computer Networks Lab Exam 21 June Friday 2-5pm")
        assert result["due_date"] is not None
        assert result["due_date"].hour == 14  # 2pm

    def test_tomorrow_12pm(self):
        result = parse_task("Assignment 3 Deadline: tomorrow 12PM")
        assert result["due_date"] is not None
        assert result["due_date"].hour == 12  # noon

    def test_before_2pm(self):
        result = parse_task("Submit assignment before 2PM on 25 June 2026")
        assert result["due_date"] is not None
        assert result["due_date"].hour == 14

    def test_no_time_defaults_to_end_of_day(self):
        result = parse_task("quiz of automata will be on Monday")
        assert result["due_date"] is not None
        assert result["due_date"].hour == 23
        assert result["due_date"].minute == 59
