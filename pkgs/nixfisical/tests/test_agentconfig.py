"""Offline tests for :mod:`nixfisical.agentconfig`.

Two of these pin things that only break silently.

* **The template is byte-identical to ``mkDotenvTemplate``.** The Nix lib and
  this module render the same Go template for the same folder; if they drift,
  a developer on a home-manager agent and one on a Debian box render different
  files from the same declaration and nobody gets an error. The expected text
  here is the Nix function's output, copied, not derived.
* **Stability.** A bundle whose template order depends on dict ordering shows
  a diff on every render, and a file that always diffs is never reviewed.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from nixfisical.agentconfig import (
    AgentConfigError,
    TemplateSpec,
    dotenv_template,
    plan_templates,
    render_agent_config,
    write_bundle,
)


def entry(project: str, environment: str, folder: str, groups: list[str]) -> dict:
    return {
        "sopsKey": f"{project}/{folder}",
        "project": project,
        "environment": environment,
        "folder": folder,
        "name": "X",
        "groups": groups,
    }


MANIFEST = [
    entry("master", "mainnet", "/bitcoin-infrastructure/bitcoind", ["developers"]),
    entry("master", "testnet4", "/bitcoin-infrastructure/bitcoind", ["developers"]),
    entry("master", "mainnet", "/bitcoin-infrastructure/bitcoind", ["developers"]),  # dup
    entry("master", "shared", "/infrastructure/rabbitmq", ["developers"]),
    entry("master", "shared", "/", ["operators"]),
    entry("platform", "prod", "/grafana", ["operators"]),
]


# -- the template ------------------------------------------------------------


def test_dotenv_template_matches_the_nix_lib_byte_for_byte() -> None:
    # nixfisicalLib.mkDotenvTemplate { projectId = "abc-123"; environment =
    # "dev"; secretPath = "/backend"; } -- as rendered by Nix, including the
    # sorted modifier keys and the trailing newline.
    expected = (
        '{{- with listSecrets "abc-123" "dev" "/backend" '
        '`{"expandSecretReferences":true,"recursive":false}` }}\n'
        "{{- range . }}\n"
        "{{ .Key }}={{ .Value }}\n"
        "{{- end }}\n"
        "{{- end }}\n"
    )
    assert dotenv_template("abc-123", "dev", "/backend") == expected


# -- planning ----------------------------------------------------------------


def test_plan_dedupes_and_orders_by_project_folder_environment() -> None:
    specs = plan_templates(MANIFEST)
    keys = [(s.project, s.folder, s.environment) for s in specs]
    assert keys == sorted(keys)
    assert len(specs) == len(set(specs)) == 5
    # A folder's environments are adjacent, which is what makes the YAML
    # readable when the same service exists on three networks.
    assert keys[:2] == [
        ("master", "/", "shared"),
        ("master", "/bitcoin-infrastructure/bitcoind", "mainnet"),
    ]
    assert keys[2] == ("master", "/bitcoin-infrastructure/bitcoind", "testnet4")


def test_plan_can_be_narrowed_to_a_group() -> None:
    specs = plan_templates(MANIFEST, {"developers"})
    assert {s.folder for s in specs} == {
        "/bitcoin-infrastructure/bitcoind",
        "/infrastructure/rabbitmq",
    }
    assert all(s.project == "master" for s in specs)


def test_plan_ignores_entries_with_no_coordinate() -> None:
    assert plan_templates([{"sopsKey": "x"}]) == []


# -- naming ------------------------------------------------------------------


def test_slug_and_destination() -> None:
    spec = TemplateSpec("master", "mainnet", "/bitcoin-infrastructure/bitcoind")
    assert spec.slug == "master__bitcoin-infrastructure__bitcoind__mainnet"
    assert (
        spec.destination("/run/secrets/env")
        == "/run/secrets/env/master/bitcoin-infrastructure/bitcoind/mainnet.env"
    )

    root = TemplateSpec("master", "shared", "/")
    assert root.slug == "master__root__shared"
    assert root.destination("/run/secrets/env/") == "/run/secrets/env/master/shared.env"


# -- rendering ---------------------------------------------------------------


def test_render_needs_every_project_id() -> None:
    with pytest.raises(AgentConfigError) as excinfo:
        render_agent_config(
            plan_templates(MANIFEST),
            address="https://i.example",
            project_ids={"master": "m1"},
            client_id_file="/etc/x/id",
            client_secret_file="/etc/x/secret",
            install_root="/etc/infisical-agent",
            dest_root="/run/secrets/env",
        )
    assert "platform" in str(excinfo.value)
    assert "--project-id" in str(excinfo.value)


def test_render_follows_the_home_manager_module_shape(tmp_path: Path) -> None:
    config, templates = render_agent_config(
        plan_templates(MANIFEST, {"developers"}),
        address="https://infisical-2.example",
        project_ids={"master": "m1"},
        client_id_file="/etc/infisical-agent/client-id",
        client_secret_file="/etc/infisical-agent/client-secret",
        install_root="/etc/infisical-agent/",
        dest_root="/run/secrets/env",
        polling_interval="90s",
    )

    assert config["infisical"] == {
        "address": "https://infisical-2.example",
        "exit-after-auth": False,
        "revoke-credentials-on-shutdown": False,
    }
    assert config["auth"]["type"] == "universal-auth"
    # Upstream's struct tag, underscores and all.
    assert config["auth"]["config"]["remove_client_secret_on_read"] is False
    assert config["sinks"] == []

    first = config["templates"][0]
    assert first["source-path"] == (
        "/etc/infisical-agent/templates/"
        "master__bitcoin-infrastructure__bitcoind__mainnet.tmpl"
    )
    assert first["destination-path"] == (
        "/run/secrets/env/master/bitcoin-infrastructure/bitcoind/mainnet.env"
    )
    assert first["config"] == {"polling-interval": "90s"}

    # Every template the YAML names is one we wrote, and vice versa.
    named = {Path(t["source-path"]).stem for t in config["templates"]}
    assert named == set(templates)
    assert templates["master__bitcoin-infrastructure__bitcoind__mainnet"] == dotenv_template(
        "m1", "mainnet", "/bitcoin-infrastructure/bitcoind"
    )

    # And the bundle round-trips through YAML with nothing lost.
    written = write_bundle(tmp_path, config, templates)
    assert (tmp_path / "agent.yaml") in written
    assert yaml.safe_load((tmp_path / "agent.yaml").read_text()) == config
    assert sorted(p.name for p in (tmp_path / "templates").iterdir()) == sorted(
        f"{slug}.tmpl" for slug in templates
    )
    destinations = (tmp_path / "destinations.txt").read_text().splitlines()
    assert destinations == [t["destination-path"] for t in config["templates"]]


def test_a_bundle_contains_no_credential_material(tmp_path: Path) -> None:
    config, templates = render_agent_config(
        [TemplateSpec("master", "shared", "/")],
        address="https://i.example",
        project_ids={"master": "m1"},
        client_id_file="/etc/infisical-agent/client-id",
        client_secret_file="/etc/infisical-agent/client-secret",
        install_root="/etc/infisical-agent",
        dest_root="/run/secrets/env",
    )
    write_bundle(tmp_path, config, templates)
    everything = "".join(p.read_text() for p in tmp_path.rglob("*") if p.is_file())
    # Paths to the credentials, yes; the credentials, never -- the renderer has
    # no way to read them, and this pins that it is not handed them either.
    assert "/etc/infisical-agent/client-secret" in everything
    assert "secretValue" not in everything
