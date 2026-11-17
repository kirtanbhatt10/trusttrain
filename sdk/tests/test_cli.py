from __future__ import annotations

import io
import json
from pathlib import Path

import pandas as pd
import pytest

from tests.fake_api import TOKEN, FakeAPI
from trusttrain import cli


@pytest.fixture()
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NO_COLOR", "1")
    (tmp_path / "data").mkdir()
    pd.DataFrame({"text": ["good product", "bad product", "fine"], "label": ["pos", "neg", "pos"]}).to_csv(
        tmp_path / "data" / "train.csv", index=False
    )
    return tmp_path


def run(*argv: str) -> tuple[int, str]:
    buf = io.StringIO()
    code = cli.main(list(argv), stdout=buf)
    return code, buf.getvalue()


def use_fake_api(monkeypatch: pytest.MonkeyPatch, api: FakeAPI) -> None:
    monkeypatch.setattr(cli, "_client", lambda config: api.client(token=TOKEN))


def test_init_creates_config(workspace: Path) -> None:
    code, out = run("init", "--dataset", "data/train.csv", "--api-url", "http://api:8000")
    assert code == 0 and "Initialised" in out
    config = json.loads((workspace / ".trusttrain" / "config.json").read_text())
    assert config["datasets"] == ["data/train.csv"] and config["api_url"] == "http://api:8000"
    assert run("init")[0] == 2  # refuses to overwrite
    assert run("init", "--force")[0] == 0


def test_fingerprint_and_verify(workspace: Path) -> None:
    code, out = run("fingerprint", "data/train.csv")
    assert code == 0 and "rows         3" in out
    manifests = list((workspace / ".trusttrain" / "manifests").glob("*.json"))
    assert len(manifests) == 1
    code, out = run("verify", "data/train.csv")
    assert code == 0 and out.startswith("VERIFIED")
    (workspace / "data" / "train.csv").write_text((workspace / "data" / "train.csv").read_text() + "injected,pos\n")
    code, out = run("verify", "data/train.csv")
    assert code == 1 and "MODIFIED" in out and "rows added: 1" in out
    code, out = run("verify", "data/train.csv", "--json")
    assert json.loads(out)["status"] == "modified"


def test_fingerprint_custom_output_and_verify_explicit_manifest(workspace: Path) -> None:
    assert run("fingerprint", "data/train.csv", "-o", "m.json")[0] == 0
    assert run("verify", "data/train.csv", "-m", "m.json")[0] == 0


def test_verify_without_manifest(workspace: Path) -> None:
    code, out = run("verify", "data/train.csv")
    assert code == 2 and "No manifest" in out


def test_errors_are_reported_not_raised(workspace: Path) -> None:
    code, out = run("fingerprint", "data/missing.csv")
    assert code == 2 and out.startswith("error:")


def test_inspect(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    use_fake_api(monkeypatch, FakeAPI(risk_level="high"))
    code, out = run("inspect", "data/train.csv")
    assert code == 0
    assert "HIGH" in out and "Token 'cf'" in out and "Overall risk: HIGH" in out
    assert run("inspect", "data/train.csv", "--fail-on", "high")[0] == 1
    assert run("inspect", "data/train.csv", "--fail-on", "critical")[0] == 0
    code, out = run("inspect", "data", "--json")
    assert json.loads(out)[0]["risk_level"] == "high"


def test_lineage(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    use_fake_api(monkeypatch, FakeAPI())
    code, out = run("lineage", "--dataset", "ds-1")
    assert code == 0 and "2 recorded artifact(s)" in out and "model v1 [active]" in out
    assert json.loads(run("lineage", "--dataset", "ds-1", "--json")[1])["total_affected"] == 2
    code, out = run("lineage", "--dataset", "missing")
    assert code == 2 and "404" in out


def test_report(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    use_fake_api(monkeypatch, FakeAPI())
    code, out = run("report", "--incident", "inc-1")
    assert code == 0 and "# Incident report" in out
    assert run("report", "--incident", "inc-1", "--format", "json", "-o", "r.json")[0] == 0
    assert json.loads((workspace / "r.json").read_text())["type"] == "incident"


def test_ci_offline_policy(workspace: Path) -> None:
    run("init", "--dataset", "data/train.csv")
    code, out = run("ci", "-o", "report.json")
    assert code == 1 and "no committed manifest" in out
    run("fingerprint", "data/train.csv")
    code, _ = run("ci", "-o", "report.json")
    report = json.loads((workspace / "report.json").read_text())
    assert code == 0 and report["passed"] and report["datasets"][0]["integrity"] == "verified"
    (workspace / "data" / "train.csv").write_text("text,label\nreplaced,neg\n")
    code, _ = run("ci", "-o", "report.json")
    report = json.loads((workspace / "report.json").read_text())
    assert code == 1 and report["datasets"][0]["integrity"] == "modified" and report["violations"]


def test_ci_with_api_risk_policy(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run("init", "--dataset", "data/train.csv")
    run("fingerprint", "data/train.csv")
    cfg_path = workspace / ".trusttrain" / "config.json"
    cfg = json.loads(cfg_path.read_text())
    cfg["policy"].update({"inspect_via_api": True, "fail_on_risk": "critical"})
    cfg_path.write_text(json.dumps(cfg))
    use_fake_api(monkeypatch, FakeAPI(risk_level="high"))
    assert run("ci", "-o", "r.json")[0] == 0
    cfg["policy"]["fail_on_risk"] = "high"
    cfg_path.write_text(json.dumps(cfg))
    code, out = run("ci", "-o", "r.json")
    assert code == 1 and "meets fail_on_risk=high" in out
    assert json.loads((workspace / "r.json").read_text())["datasets"][0]["inspection"]["risk_level"] == "high"


def test_ci_missing_dataset_file(workspace: Path) -> None:
    run("init")
    code, out = run("ci", "--dataset", "data/nope.csv", "-o", "r.json")
    assert code == 1 and "not found" in out


def test_api_url_env_override(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRUSTTRAIN_API_URL", "http://other:9000")
    assert cli.load_config()["api_url"] == "http://other:9000"


def test_version() -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
