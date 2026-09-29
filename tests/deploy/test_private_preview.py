from __future__ import annotations

import os
import socket
import subprocess
from pathlib import Path

import pytest
import tomli

from deploy.preview import control
from deploy.preview.control import (
    ConfigurationError,
    build_plan,
    database_url,
    dump_toml,
    render_config,
    validate_app_inventory,
    validate_ip_inventory,
    validate_pr_record,
)
from tests.live.test_artifact_tenancy import _other_pr_base_url

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
PREVIEW = ROOT / "deploy" / "preview"


def test_preview_plan_derives_every_target_from_bounded_pr() -> None:
    plan = build_plan("188", "psat-staging", "psat-stage-pr")
    assert plan.app == "psat-stage-pr-188"
    assert plan.private_url == "http://psat-stage-pr-188.flycast"
    assert plan.database == "psat_pr_188"
    assert plan.artifact_prefix == "pr-188/"


@pytest.mark.parametrize(
    ("pr", "org", "prefix"),
    [
        ("0", "psat-staging", "psat-stage-pr"),
        ("1;echo pwned", "psat-staging", "psat-stage-pr"),
        ("1", "personal", "psat-stage-pr"),
        ("1", "protosec", "psat-stage-pr"),
        ("1", "psat-staging", "psat-prod"),
        ("1", "psat-staging", "psat-stage"),
        ("1", "psat-staging", "psat-stage-pr;echo"),
    ],
)
def test_preview_plan_rejects_production_and_command_injection(pr: str, org: str, prefix: str) -> None:
    with pytest.raises(ConfigurationError):
        build_plan(pr, org, prefix)


def _render_preview() -> tuple[dict, dict]:
    plan = build_plan(42, "psat-staging", "psat-stage-pr")
    source = (ROOT / "fly.toml").read_text()
    return tomli.loads(source), tomli.loads(render_config(source, plan))


def test_generated_config_is_private_flycast_http_with_idle_wake() -> None:
    plan = build_plan(42, "psat-staging", "psat-stage-pr")
    rendered = render_config((ROOT / "fly.toml").read_text(), plan)
    config = tomli.loads(rendered)
    assert config["app"] == "psat-stage-pr-42"
    assert (ROOT / config["build"]["dockerfile"]).is_file()
    assert config["env"]["PSAT_EDGE_MODE"] == "preview"
    assert config["http_service"] == {
        "internal_port": 8000,
        "force_https": False,
        "auto_stop_machines": "stop",
        "auto_start_machines": True,
        "min_machines_running": 0,
        "processes": ["web"],
        "concurrency": {"type": "connections", "hard_limit": 100, "soft_limit": 80},
        "checks": [
            {
                "method": "get",
                "path": "/api/health",
                "interval": "30s",
                "timeout": "5s",
                "grace_period": "60s",
            }
        ],
    }
    assert ".fly.dev" not in rendered
    assert "REPLACE_WITH_PSAT_HEALTH_SECRET" not in rendered


def _changed(a: dict, b: dict) -> set[str]:
    return {key for key in a.keys() | b.keys() if a.get(key) != b.get(key)}


def test_preview_differs_from_production_only_by_allowlisted_settings() -> None:
    # A live run is only evidence about production if the preview runs the same
    # process layout (lifecycle mode, indexer placement), sizing and settings.
    production, preview = _render_preview()
    assert _changed(production, preview) == {"app", "env", "http_service"}
    assert _changed(production["env"], preview["env"]) == {"PSAT_EDGE_MODE", "PSAT_SITE_ORIGIN", "PSAT_PIN_BLOCKS"}
    assert "PSAT_SITE_ORIGIN" not in preview["env"]
    prod_http, preview_http = production["http_service"], preview["http_service"]
    assert _changed(prod_http, preview_http) == {"force_https", "min_machines_running", "checks"}
    unheadered = [{k: v for k, v in check.items() if k != "headers"} for check in prod_http["checks"]]
    assert preview_http["checks"] == unheadered


def test_toml_dump_round_trips_production_config() -> None:
    source = tomli.loads((ROOT / "fly.toml").read_text())
    assert tomli.loads(dump_toml(source)) == source


def test_render_rejects_overrides_that_can_force_public_https(monkeypatch: pytest.MonkeyPatch) -> None:
    plan = build_plan(42, "psat-staging", "psat-stage-pr")
    monkeypatch.setitem(control.PREVIEW_HTTP, "force_https", True)
    with pytest.raises(ConfigurationError, match="unsafe preview config"):
        render_config((ROOT / "fly.toml").read_text(), plan)


def test_app_inventory_requires_exact_staging_owner() -> None:
    plan = build_plan(42, "psat-staging", "psat-stage-pr")
    assert validate_app_inventory([], plan, allow_missing=True) is False
    assert validate_app_inventory([{"Name": plan.app, "Organization": "psat-staging"}], plan, allow_missing=False)
    with pytest.raises(ConfigurationError, match="ownership mismatch"):
        validate_app_inventory([{"Name": plan.app, "Organization": "personal"}], plan, allow_missing=False)
    with pytest.raises(ConfigurationError, match="missing"):
        validate_app_inventory([], plan, allow_missing=False)


def test_ip_inventory_requires_one_flycast_address_and_no_public_ingress() -> None:
    validate_ip_inventory([{"Address": "fdaa:1:2::3", "Type": "private"}])
    with pytest.raises(ConfigurationError, match="public ingress"):
        validate_ip_inventory(
            [
                {"Address": "fdaa:1:2::3", "Type": "private"},
                {"Address": "66.241.124.1", "Type": "v4"},
            ]
        )
    with pytest.raises(ConfigurationError, match="public ingress"):
        validate_ip_inventory([{"Address": "66.241.124.1", "Type": "private"}])
    with pytest.raises(ConfigurationError, match="no Flycast"):
        validate_ip_inventory([])
    validate_ip_inventory([], allow_empty=True)


def _pr_record(*, number: int = 42, state: str = "open", repository: str = "org/repo", sha: str = "a" * 40):
    return {
        "number": number,
        "state": state,
        "base": {"ref": "main"},
        "head": {"sha": sha, "repo": {"full_name": repository}},
    }


def test_dispatch_validation_requires_current_open_same_repo_pr() -> None:
    record = _pr_record()
    assert validate_pr_record(record, pr_number="42", repository="org/repo", head_sha="a" * 40) == "a" * 40
    with pytest.raises(ConfigurationError, match="fork"):
        validate_pr_record(_pr_record(repository="attacker/fork"), pr_number=42, repository="org/repo", head_sha=None)
    with pytest.raises(ConfigurationError, match="open PR"):
        validate_pr_record(_pr_record(state="closed"), pr_number=42, repository="org/repo", head_sha=None)
    with pytest.raises(ConfigurationError, match="stale"):
        validate_pr_record(record, pr_number=42, repository="org/repo", head_sha="b" * 40)


def test_database_url_quotes_credentials() -> None:
    assert database_url(user="preview@role", password="p/a:ss?", host="staging.example", database="psat_pr_42") == (
        "postgresql://preview%40role:p%2Fa%3Ass%3F@staging.example/psat_pr_42?sslmode=require"
    )


def test_private_proxy_dry_run_is_bounded_and_rejects_injection(tmp_path: Path) -> None:
    script = PREVIEW / "private_proxy.sh"
    result = subprocess.run(
        [script, "--dry-run", "start", "psat-stage-pr-42", "psat-staging", "18080", str(tmp_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    assert result.stdout.strip() == (
        "flyctl proxy 18080:80 psat-stage-pr-42.flycast --app psat-stage-pr-42 --org psat-staging "
        "--bind-addr 127.0.0.1 --quiet"
    )
    bad = subprocess.run(
        [script, "--dry-run", "start", "psat-stage-pr-42;id", "psat-staging", "18080", str(tmp_path)],
        capture_output=True,
        text=True,
    )
    assert bad.returncode == 2


def test_private_proxy_connection_failure_is_bounded(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    flyctl = fake_bin / "flyctl"
    flyctl.write_text("#!/bin/sh\nexit 17\n")
    flyctl.chmod(0o755)
    env = {**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}", "FLY_API_TOKEN": "fake-local-token"}
    result = subprocess.run(
        [PREVIEW / "private_proxy.sh", "start", "psat-stage-pr-42", "psat-staging", "18080", str(tmp_path / "state")],
        env=env,
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 1
    assert "exited before it became ready" in result.stderr


def test_private_proxy_starts_and_stops_expected_process(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    flyctl = fake_bin / "flyctl"
    flyctl.write_text(
        "#!/bin/sh\n"
        "port=${2%%:*}\n"
        'python -m http.server "$port" --bind 127.0.0.1 >/dev/null 2>&1 &\n'
        "child=$!\n"
        'trap \'kill "$child" 2>/dev/null; wait "$child" 2>/dev/null; exit 0\' TERM INT\n'
        'wait "$child"\n'
    )
    flyctl.chmod(0o755)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    state = tmp_path / "state"
    env = {**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}", "FLY_API_TOKEN": "fake-local-token"}
    args = ["psat-stage-pr-42", "psat-staging", str(port), str(state)]
    subprocess.run([PREVIEW / "private_proxy.sh", "start", *args], env=env, check=True, timeout=5)
    assert (state / "fly-proxy.pid").is_file()
    subprocess.run([PREVIEW / "private_proxy.sh", "stop", *args], env=env, check=True, timeout=10)
    assert not (state / "fly-proxy.pid").exists()


def test_private_proxy_cleanup_is_idempotent(tmp_path: Path) -> None:
    for _ in range(2):
        subprocess.run(
            [PREVIEW / "private_proxy.sh", "stop", "psat-stage-pr-42", "psat-staging", "18080", str(tmp_path)],
            check=True,
        )


def test_cross_preview_requires_explicit_private_route(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PSAT_LIVE_PR_NUMBER", "42")
    monkeypatch.setenv("PSAT_LIVE_OTHER_PR", "43")
    monkeypatch.delenv("PSAT_LIVE_OTHER_URL", raising=False)
    assert _other_pr_base_url("http://127.0.0.1:18080") is None
    monkeypatch.setenv("PSAT_LIVE_OTHER_URL", "http://127.0.0.1:18081")
    assert _other_pr_base_url("http://127.0.0.1:18080") == "http://127.0.0.1:18081"


def test_all_preview_lifecycle_workflows_keep_private_fly_boundary() -> None:
    names = (
        "pr.yml",
        "rerun-live-tests.yml",
        "reset-pr-db.yml",
        "pr-cleanup.yml",
        "fork-prod-to-pr.yml",
        "pr-comment-commands.yml",
    )
    text = "\n".join((WORKFLOWS / name).read_text() for name in names)
    assert ".fly.dev" not in text
    assert "--org personal" not in text
    assert "secrets.FLY_API_TOKEN" not in text
    assert "secrets.NEON_API_KEY" not in text
    assert "|| true" not in text
    assert "FLY_STAGING_DEPLOY_TOKEN" in text
    assert "secrets.PSAT_STAGING_ADMIN_KEY" in text
    assert "secrets.ARTIFACT_STORAGE_BUCKET" in text
    assert "TODO(security): replace these shared database/provider/storage" in text


def test_deploy_and_http_jobs_enforce_private_path() -> None:
    pr = (WORKFLOWS / "pr.yml").read_text()
    assert "--flycast --no-public-ips" in pr
    assert "validate-ip-inventory" in pr
    assert "validate-app-inventory" in pr
    assert 'PSAT_EDGE_MODE="preview"' in pr
    assert '--output "$GITHUB_WORKSPACE/fly-preview.toml"' in pr
    assert '--config "$GITHUB_WORKSPACE/fly-preview.toml"' in pr
    assert "$RUNNER_TEMP/fly-preview.toml" not in pr
    assert "flyctl proxy 8080:80 ${{ steps.plan.outputs.app }}.flycast --app ${{ steps.plan.outputs.app }}" in pr
    for name in ("pr.yml", "rerun-live-tests.yml", "reset-pr-db.yml"):
        workflow = (WORKFLOWS / name).read_text()
        assert "private_proxy.sh start" in workflow
        assert "private_proxy.sh stop" in workflow
        assert "http://127.0.0.1:" in workflow


def test_preview_deploy_provisions_managed_worker_lifecycle() -> None:
    pr = (WORKFLOWS / "pr.yml").read_text()
    deploy_job = pr.split("\n  deploy:\n", 1)[1].split("\n  live-tests:\n", 1)[0]
    # Session advisory locks need the direct endpoint, never the pooler.
    assert 'PSAT_LIFECYCLE_DATABASE_URL="$LIFECYCLE_DB_URL"' in deploy_job
    assert '--host "$NEON_STAGING_ADMIN_HOST"' in deploy_job
    assert "!= *-pooler*" in deploy_job
    # Scoped to the one preview app with read + control only; the staging token
    # is org-wide and cannot mint app tokens.
    assert '{apps: {($id): "rC"}}' in deploy_job
    assert "flyctl tokens attenuate" in deploy_job
    assert "flyctl tokens create" not in deploy_job
    assert "::add-mask::$token" in deploy_job
    assert "flyctl secrets import --stage" in deploy_job
    assert "PSAT_WORKER_LIFECYCLE_TOKEN=$" not in deploy_job
    assert deploy_job.index("Stage app-scoped worker lifecycle token") < deploy_job.index("Deploy private preview")
    assert deploy_job.index("Start non-web process groups") < deploy_job.index("Activate worker lifecycle")
    for workflow in (deploy_job, (WORKFLOWS / "reset-pr-db.yml").read_text()):
        assert "UPDATE worker_lifecycle SET paused = false WHERE id = 1;" in workflow


def test_tunnel_jobs_use_staging_org_token_without_inventory_commands() -> None:
    pr = (WORKFLOWS / "pr.yml").read_text()
    live_job = pr.split("\n  live-tests:\n", 1)[1].split("\n  destroy-preview-workers:\n", 1)[0]
    rerun = (WORKFLOWS / "rerun-live-tests.yml").read_text()
    for workflow in (live_job, rerun):
        assert "FLY_STAGING_DEPLOY_TOKEN" in workflow
        assert "FLY_STAGING_TUNNEL_TOKEN" not in workflow
        assert "flyctl apps list" not in workflow
        assert "private_proxy.sh start" in workflow


def test_manual_dispatch_inputs_are_validated_before_target_lookup() -> None:
    for name in ("rerun-live-tests.yml", "reset-pr-db.yml"):
        workflow = (WORKFLOWS / name).read_text()
        assert 'parse_pr_number(sys.argv[1])\' "$PR_NUMBER"' in workflow
        assert "INPUT_HEAD_SHA: ${{ inputs.head_sha }}" in workflow
        assert '--head-sha "$INPUT_HEAD_SHA"' in workflow
        assert '--head-sha "${{ inputs.head_sha }}"' not in workflow


def test_fork_prod_is_disabled() -> None:
    fork = (WORKFLOWS / "fork-prod-to-pr.yml").read_text()
    assert "NEON" not in fork
    assert "exit 1" in fork
    assert "/fork-prod is disabled" in fork


def test_production_deploy_injects_private_health_secret_and_uses_cloudflare() -> None:
    config = tomli.loads((ROOT / "fly.toml").read_text())
    assert config["env"]["PSAT_EDGE_MODE"] == "cloudflare"
    assert config["env"]["PSAT_SITE_ORIGIN"] == "https://snif.sh"
    assert "http_checks" not in config["http_service"]
    check = config["http_service"]["checks"][0]
    assert check["path"] == "/api/health"
    assert check["headers"]["X-PSAT-Health-Secret"] == "REPLACE_WITH_PSAT_HEALTH_SECRET"
    web_vm = next(vm for vm in config["vm"] if vm["processes"] == ["web"])
    assert web_vm["memory"] == "1gb"

    main = (WORKFLOWS / "main.yml").read_text()
    assert "PSAT_HEALTH_SECRET: ${{ secrets.PSAT_HEALTH_SECRET }}" in main
    assert "source.count(marker) != 1" in main
    assert 'python - "$GITHUB_WORKSPACE/fly.production.toml"' in main
    assert '--config "$GITHUB_WORKSPACE/fly.production.toml"' in main
    assert "$RUNNER_TEMP/fly.production.toml" not in main
    assert "PROD_URL: https://snif.sh" in main
    assert "PSAT_ADMIN_KEY: ${{ secrets.PSAT_ADMIN_KEY }}" not in main
    assert "if: false" not in main


def test_comment_commands_are_exact_and_revalidate_pr() -> None:
    commands = (WORKFLOWS / "pr-comment-commands.yml").read_text()
    assert "comment.body.trim()" in commands
    assert "contains(github.event.comment.body" not in commands
    assert "pr.state !== 'open'" in commands
    assert "pr.base.ref !== 'main'" in commands
    assert "pr.head.repo?.full_name" in commands
    assert "--ref main" in commands
    assert 'head_sha="$HEAD_SHA"' in commands
