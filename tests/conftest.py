import warnings

import pytest
import sqlite3
from pathlib import Path


@pytest.fixture
def temp_db(monkeypatch, tmp_path: Path):
    """
    Creates a temporary SQLite database for testing and overrides DB_PATH.
    """
    temp_db_path = str(tmp_path / "test_keys.db")

    conn = sqlite3.connect(temp_db_path)
    cursor = conn.cursor()
    # Match schema from app.keys.init_db()
    cursor.execute(
        """
        CREATE TABLE keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    """
    )
    conn.commit()
    conn.close()

    # Override DB_PATH in modules
    monkeypatch.setattr("app.keys.DB_PATH", temp_db_path)
    monkeypatch.setattr("app.main.DB_PATH", temp_db_path)

    yield temp_db_path


@pytest.fixture(autouse=True)
def reset_keys_store():
    """
    Resets the in-memory keys_store before each test.
    """
    from app.keys import keys_store

    keys_store.clear()
    yield
    keys_store.clear()
