"""Startup must load the declared PostgreSQL driver without contacting host services."""

from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
import sys
from unittest.mock import Mock

import docker
import pytest
import sqlalchemy

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ops"))
import selfsentry_cli as cli  # noqa: E402


@pytest.mark.parametrize("scheme", ["postgresql", "postgresql+psycopg2"])
def test_preflight_loads_real_declared_driver_and_preserves_url(tmp_path, monkeypatch, scheme):
    (tmp_path / ".env").write_text("")
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    monkeypatch.setenv("SELFSENTRY_API_TOKEN", "test-only")
    monkeypatch.setenv(
        "DATABASE_URL", f"{scheme}://test:synthetic@localhost:5433/test?sslmode=require"
    )
    create_engine = sqlalchemy.create_engine
    observed = []
    query = Mock()

    def engine_factory(url, **kwargs):
        # This uses SQLAlchemy's actual dialect/DBAPI selection, not a fake engine.
        engine = create_engine(url, **kwargs)
        assert engine.dialect.driver == "psycopg2"
        assert url.host == "localhost" and url.port == 5433 and url.database == "test"
        assert url.password == "synthetic" and url.query == {"sslmode": "require"}
        assert kwargs["connect_args"] == {"connect_timeout": 5}
        monkeypatch.setattr(engine, "connect", lambda: nullcontext(SimpleNamespace(execute=query)))
        dispose = Mock(wraps=engine.dispose)
        monkeypatch.setattr(engine, "dispose", dispose)
        observed.append(dispose)
        return engine

    monkeypatch.setattr(sqlalchemy, "create_engine", engine_factory)
    monkeypatch.setattr(docker, "from_env", lambda **_: SimpleNamespace(ping=Mock(), close=Mock()))
    monkeypatch.setattr(cli.shutil, "which", lambda _: None)
    with pytest.raises(cli.StartupError, match="Missing prerequisite: docker"):
        cli.check_prerequisites()
    assert str(query.call_args.args[0]) == "SELECT 1"
    observed[0].assert_called_once()


def test_failed_database_probe_disposes_engine_and_keeps_errors_private(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("")
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    monkeypatch.setenv("SELFSENTRY_API_TOKEN", "test-only")
    monkeypatch.setenv("DATABASE_URL", "postgresql://test:synthetic@localhost/test")
    engine = Mock()
    engine.connect.side_effect = RuntimeError("synthetic private driver detail")
    monkeypatch.setattr(sqlalchemy, "create_engine", lambda *a, **kw: engine)
    with pytest.raises(cli.StartupError) as caught:
        cli.check_prerequisites()
    assert str(caught.value) == "PostgreSQL connection failed. Check DATABASE_URL and service."
    engine.dispose.assert_called_once()
