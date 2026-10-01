import pytest

from .helpers import make_context


@pytest.fixture(scope="session")
def ctx():
    return make_context()
