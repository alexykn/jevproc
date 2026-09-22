import pytest

from jevproc.core.config import Config, load_config
from jevproc.core.demo import demo_snapshot


@pytest.fixture
def config():
    data = load_config().model_dump(mode="json")
    data["jev"].update(requests_per_minute=0, max_retry_delay=0, retries=1)
    data["cache"]["enabled"] = False
    return Config.model_validate(data)


@pytest.fixture
def snapshot():
    return demo_snapshot()
