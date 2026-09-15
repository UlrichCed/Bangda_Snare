import copy
import os
import sys

import pytest
import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)


@pytest.fixture(scope="session")
def base_config() -> dict:
    """La config réellement livrée : les tests valident aussi ses valeurs."""
    with open(os.path.join(REPO_ROOT, "config.yaml"), "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


@pytest.fixture
def config(base_config) -> dict:
    return copy.deepcopy(base_config)


BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
}

SCANNER_HEADERS = {"User-Agent": "python-requests/2.31.0"}
