import pytest


@pytest.fixture(autouse=True)
def _reset_ai_runtime():
    from utils.llm_client import reset_runtime_state
    from utils.rate_limiter import reset_rate_limiter
    reset_runtime_state()
    reset_rate_limiter()
    yield
    reset_runtime_state()
    reset_rate_limiter()
