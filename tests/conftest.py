import os

import pytest

# Vendored test fixture: keeps this repo self-contained so a fresh clone can run
# the timetable tests without the sibling Test/ folder of the dev workspace.
LATEST_TIMETABLE_PDF = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "fixtures", "Latest-Timetable.pdf")
)


@pytest.fixture(autouse=True)
def _reset_ai_runtime():
    from utils.llm_client import reset_runtime_state
    from utils.rate_limiter import reset_rate_limiter
    reset_runtime_state()
    reset_rate_limiter()
    yield
    reset_runtime_state()
    reset_rate_limiter()


@pytest.fixture(scope="module")
def latest_timetable_pdf():
    """Path to the latest RSCI timetable PDF.

    The latest-RSCI layout (bare numeric room labels) is covered only by the
    tests that request this fixture, so a missing file fails loudly rather than
    skipping - a green run must mean the parser was actually exercised.
    """
    if not os.path.exists(LATEST_TIMETABLE_PDF):
        pytest.fail(
            f"required timetable fixture is missing: {LATEST_TIMETABLE_PDF}\n"
            "Keep tests/fixtures/Latest-Timetable.pdf committed so the parser stays exercised.",
            pytrace=False,
        )
    return LATEST_TIMETABLE_PDF
