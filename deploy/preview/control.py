"""Fail-closed planning and validation for private PR previews.

This module has no remote write implementation. Workflows use its validated
outputs before invoking flyctl, psql, or aws explicitly.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import quote

_PR_RE = re.compile(r"[1-9][0-9]{0,5}")
_SLUG_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_ROLE_RE = re.compile(r"[a-z_][a-z0-9_]{0,62}")
_SHA_RE = re.compile(r"[0-9a-f]{40}")
_FORBIDDEN_ORGS = frozenset({"personal", "protosec"})
_FORBIDDEN_APPS = frozenset({"psat"})


class ConfigurationError(ValueError):
    pass


def _require_fullmatch(pattern: re.Pattern[str], value: str, label: str) -> str:
    if not pattern.fullmatch(value):
        raise ConfigurationError(f"invalid {label}: {value!r}")
    return value


def parse_pr_number(value: str | int) -> int:
    text = str(value)
    _require_fullmatch(_PR_RE, text, "PR number")
    return int(text)


def validate_org(value: str) -> str:
    org = _require_fullmatch(_SLUG_RE, value, "staging Fly organization")
    if org in _FORBIDDEN_ORGS:
        raise ConfigurationError(f"refusing non-staging Fly organization: {org}")
    return org


def validate_prefix(value: str) -> str:
    prefix = _require_fullmatch(_SLUG_RE, value, "preview app prefix")
    if prefix in _FORBIDDEN_APPS or prefix.startswith("psat-prod") or not prefix.endswith("-pr"):
        raise ConfigurationError(f"refusing production-like preview prefix: {prefix}")
    return prefix


def validate_runtime_role(value: str) -> str:
    return _require_fullmatch(_ROLE_RE, value, "staging database runtime role")


@dataclass(frozen=True)
class PreviewPlan:
    pr_number: int
    organization: str
    app: str
    flycast_host: str
    private_url: str
    database: str
    artifact_prefix: str


def build_plan(pr_number: str | int, organization: str, app_prefix: str) -> PreviewPlan:
    pr = parse_pr_number(pr_number)
    org = validate_org(organization)
    prefix = validate_prefix(app_prefix)
    app = f"{prefix}-{pr}"
    if len(app) > 63 or app in _FORBIDDEN_APPS:
        raise ConfigurationError(f"invalid or forbidden generated Fly app: {app}")
    return PreviewPlan(
        pr_number=pr,
        organization=org,
        app=app,
        flycast_host=f"{app}.flycast",
        private_url=f"http://{app}.flycast",
        database=f"psat_pr_{pr}",
        artifact_prefix=f"pr-{pr}/",
    )


def render_config(template: str, plan: PreviewPlan) -> str:
    if template.count("__PSAT_PREVIEW_APP__") != 1:
        raise ConfigurationError("preview template must contain exactly one app placeholder")
    rendered = template.replace("__PSAT_PREVIEW_APP__", plan.app)
    required = (
        "force_https = false",
        'auto_stop_machines = "stop"',
        "auto_start_machines = true",
        "min_machines_running = 0",
        'path = "/api/health"',
        'processes = ["web"]',
    )
    missing = [item for item in required if item not in rendered]
    forbidden = ("force_https = true", ".fly.dev", 'app = "psat"')
    present = [item for item in forbidden if item in rendered]
    if missing or present:
        raise ConfigurationError(f"unsafe preview config; missing={missing}, forbidden={present}")
    return rendered


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"cannot read JSON from {path}: {exc}") from exc


def _app_records(payload: Any) -> list[Mapping[str, Any]]:
    if isinstance(payload, list):
        records = payload
    elif isinstance(payload, dict) and isinstance(payload.get("apps"), list):
        records = payload["apps"]
    else:
        raise ConfigurationError("unexpected Fly app inventory shape")
    if not all(isinstance(record, dict) for record in records):
        raise ConfigurationError("Fly app inventory contains a non-object")
    return records


def _field(record: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        if name in record:
            return record[name]
    return None


def validate_app_inventory(payload: Any, plan: PreviewPlan, *, allow_missing: bool) -> bool:
    matches = []
    for record in _app_records(payload):
        name = _field(record, "Name", "name")
        if name != plan.app:
            continue
        organization = _field(record, "Organization", "organization", "org_slug")
        if isinstance(organization, dict):
            organization = _field(organization, "Slug", "slug", "Name", "name")
        matches.append(organization)
    if not matches:
        if allow_missing:
            return False
        raise ConfigurationError(f"preview app {plan.app!r} is missing from organization {plan.organization!r}")
    if len(matches) != 1 or matches[0] != plan.organization:
        raise ConfigurationError(
            f"preview app ownership mismatch for {plan.app!r}: expected {plan.organization!r}, found {matches!r}"
        )
    return True


def validate_ip_inventory(payload: Any, *, allow_empty: bool = False) -> None:
    if isinstance(payload, dict):
        payload = payload.get("ips", payload.get("IPAddresses"))
    if not isinstance(payload, list):
        raise ConfigurationError("unexpected Fly IP inventory shape")
    if not payload and allow_empty:
        return
    if not payload:
        raise ConfigurationError("preview has no Flycast address")
    private_count = 0
    public = []
    for record in payload:
        if not isinstance(record, dict):
            raise ConfigurationError("Fly IP inventory contains a non-object")
        address = str(_field(record, "Address", "address", "IP", "ip") or "")
        kind = str(_field(record, "Type", "type", "Kind", "kind") or "").lower()
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as exc:
            raise ConfigurationError(f"invalid Fly IP address: {address!r}") from exc
        is_private = kind in {"private", "flycast", "private_v6"} and (
            parsed.version == 6 and parsed in ipaddress.ip_network("fdaa::/16")
        )
        if is_private:
            private_count += 1
        else:
            public.append(address)
    if public:
        raise ConfigurationError(f"preview has public ingress addresses: {public}")
    if private_count != 1:
        raise ConfigurationError(f"preview must have exactly one Flycast address, found {private_count}")


def validate_pr_record(payload: Any, *, pr_number: str | int, repository: str, head_sha: str | None) -> str:
    pr = parse_pr_number(pr_number)
    if not isinstance(payload, dict) or payload.get("number") != pr:
        raise ConfigurationError("GitHub PR record does not match requested PR")
    if payload.get("state") != "open" or payload.get("base", {}).get("ref") != "main":
        raise ConfigurationError("preview target must be an open PR into main")
    if payload.get("head", {}).get("repo", {}).get("full_name") != repository:
        raise ConfigurationError("privileged preview workflows reject fork PRs")
    actual_sha = str(payload.get("head", {}).get("sha", ""))
    _require_fullmatch(_SHA_RE, actual_sha, "PR head SHA")
    if head_sha is not None and head_sha != actual_sha:
        raise ConfigurationError("dispatched head SHA is stale or does not match the PR")
    return actual_sha


def database_url(*, user: str, password: str, host: str, database: str) -> str:
    if not user or not password or not host:
        raise ConfigurationError("database URL inputs must be non-empty")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", host) or "/" in database:
        raise ConfigurationError("invalid database URL target")
    return f"postgresql://{quote(user, safe='')}:{quote(password, safe='')}@{host}/{database}?sslmode=require"


def _write_github_output(path: Path, values: Mapping[str, str | int | bool]) -> None:
    with path.open("a") as output:
        for key, value in values.items():
            if isinstance(value, bool):
                value = str(value).lower()
            output.write(f"{key}={value}\n")


def _plan_from_args(args: argparse.Namespace) -> PreviewPlan:
    return build_plan(args.pr_number, args.organization, args.app_prefix)


def _add_plan_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--pr-number", required=True)
    parser.add_argument("--organization", required=True)
    parser.add_argument("--app-prefix", required=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan_parser = subparsers.add_parser("plan")
    _add_plan_args(plan_parser)
    plan_parser.add_argument("--github-output", type=Path)

    render_parser = subparsers.add_parser("render-config")
    _add_plan_args(render_parser)
    render_parser.add_argument("--template", type=Path, required=True)
    render_parser.add_argument("--output", type=Path, required=True)

    app_parser = subparsers.add_parser("validate-app-inventory")
    _add_plan_args(app_parser)
    app_parser.add_argument("--inventory", type=Path, required=True)
    app_parser.add_argument("--allow-missing", action="store_true")
    app_parser.add_argument("--github-output", type=Path)

    ip_parser = subparsers.add_parser("validate-ip-inventory")
    ip_parser.add_argument("--inventory", type=Path, required=True)
    ip_parser.add_argument("--allow-empty", action="store_true")

    pr_parser = subparsers.add_parser("validate-pr-record")
    pr_parser.add_argument("--record", type=Path, required=True)
    pr_parser.add_argument("--pr-number", required=True)
    pr_parser.add_argument("--repository", required=True)
    pr_parser.add_argument("--head-sha")
    pr_parser.add_argument("--github-output", type=Path)

    url_parser = subparsers.add_parser("database-url")
    url_parser.add_argument("--user", required=True)
    url_parser.add_argument("--host", required=True)
    url_parser.add_argument("--database", required=True)
    url_parser.add_argument("--password-env", default="PSAT_DATABASE_PASSWORD")

    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            plan = _plan_from_args(args)
            values = asdict(plan)
            if args.github_output:
                _write_github_output(args.github_output, values)
            else:
                print(json.dumps({"mode": "plan-only; no remote operations implemented", **values}, indent=2))
        elif args.command == "render-config":
            plan = _plan_from_args(args)
            args.output.write_text(render_config(args.template.read_text(), plan))
        elif args.command == "validate-app-inventory":
            exists = validate_app_inventory(
                _load_json(args.inventory), _plan_from_args(args), allow_missing=args.allow_missing
            )
            if args.github_output:
                _write_github_output(args.github_output, {"exists": exists})
            else:
                print(json.dumps({"exists": exists}))
        elif args.command == "validate-ip-inventory":
            validate_ip_inventory(_load_json(args.inventory), allow_empty=args.allow_empty)
        elif args.command == "validate-pr-record":
            sha = validate_pr_record(
                _load_json(args.record),
                pr_number=args.pr_number,
                repository=args.repository,
                head_sha=args.head_sha,
            )
            if args.github_output:
                _write_github_output(args.github_output, {"head_sha": sha})
            else:
                print(sha)
        elif args.command == "database-url":
            password = os.environ.get(args.password_env, "")
            print(database_url(user=args.user, password=password, host=args.host, database=args.database))
    except ConfigurationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
