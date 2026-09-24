"""Offline tests for ``source = "literal"`` entries.

The criterion is the same as the other suites: cover what fails *silently*.
A literal is the one kind of entry whose value is in the manifest, and the
manifest is in a world-readable store path on every host -- so the failures
that matter are the ones where a value ends up somewhere it should not, or a
file gets opened that should not.

* **A ``value`` on a non-literal is rejected.** ``mkInfisical`` cannot produce
  one, so this only fires on a hand-built entry; but that entry would be a
  plaintext secret in the store and must not validate.
* **A literal never opens SOPS.** ``read_key`` is not stubbed; the sopsFile is
  absent, so if reconcile reached for a file this would raise.
* **A literal is pushed like a SOPS value.** Same upsert, same counters, same
  dry-run classification -- so the operator's report reads the same.
* **``pull`` does not claim it.** The push/pull partition already tested in
  ``test_pull`` gains a third source and must stay disjoint.
* **``resolve_paths`` leaves it alone.** Handing a literal the fallback
  ``--secrets-file`` would make the manifest *look* SOPS-backed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from nixfisical.manifest import LITERAL_SOURCE, entry_source, resolve_paths, validate
from nixfisical.pull import _wanted
from nixfisical.reconcile import reconcile


class RecordingClient:
    """Enough of ``InfisicalClient`` for reconcile, remembering every upsert."""

    def __init__(self, projects: dict[str, str]) -> None:
        self.projects = projects
        self.upserts: list[dict[str, Any]] = []

    def list_projects(self, organization_id: str) -> dict[str, str]:
        return dict(self.projects)

    def create_project(self, name: str) -> str:  # pragma: no cover - not reached
        raise AssertionError("project should already exist in these tests")

    def create_environment(self, project_id: str, *, name: str, slug: str) -> bool:
        return False

    def create_folder(
        self, *, project_id: str, environment: str, path: str, name: str
    ) -> bool:
        return False

    def upsert_secret(self, name: str, **kwargs: Any) -> str:
        self.upserts.append({"name": name, **kwargs})
        return "created"

    def list_secrets(
        self, *, project_id: str, environment: str, path: str = "/"
    ) -> list[dict[str, Any]]:
        return []


def literal(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "sopsKey": "literal:bitcoin-nodes/mainnet/bitcoind:BITCOIND_RPC_PORT",
        "sopsFile": None,
        "project": "bitcoin-nodes",
        "environment": "mainnet",
        "folder": "/bitcoind",
        "name": "BITCOIND_RPC_PORT",
        "value": "8332",
        "groups": ["developers"],
        "hosts": [],
        "source": LITERAL_SOURCE,
    }
    base.update(overrides)
    return base


# -- validation --------------------------------------------------------------


def test_a_literal_validates_without_a_sops_file() -> None:
    assert validate([literal()]) == []


def test_a_literal_needs_a_non_empty_value() -> None:
    assert any("non-empty string 'value'" in p for p in validate([literal(value="")]))
    assert any("non-empty string 'value'" in p for p in validate([literal(value=None)]))
    assert any("non-empty string 'value'" in p for p in validate([literal(value=8332)]))


def test_a_literal_must_not_name_a_sops_file() -> None:
    problems = validate([literal(sopsFile="/secrets/x.yaml")])
    assert any("must not name a sopsFile" in p for p in problems)


def test_a_value_on_a_sops_owned_entry_is_rejected() -> None:
    # The one that matters: this would be a plaintext secret in the store.
    leaked = literal(source="sops", sopsFile="/secrets/bitcoin.yaml", sopsKey="btc/rpc")
    problems = validate([leaked])
    assert any("only valid on a source='literal' entry" in p for p in problems)

    # And with no source at all, which defaults to sops.
    leaked.pop("source")
    assert any("only valid on a source='literal'" in p for p in validate([leaked]))


def test_a_value_on_an_infisical_owned_entry_is_rejected() -> None:
    problems = validate([literal(source="infisical", sopsFile="/secrets/x.yaml")])
    assert any("only valid on a source='literal'" in p for p in problems)


# -- the partition -----------------------------------------------------------


def test_pull_does_not_claim_a_literal() -> None:
    assert entry_source(literal()) == LITERAL_SOURCE
    assert _wanted([literal()]) == []


def test_resolve_paths_leaves_a_literal_alone() -> None:
    resolved = resolve_paths(
        [literal()], Path("/repo"), default_secrets_file="secrets/default.yaml"
    )
    assert resolved[0]["sopsFile"] is None
    assert resolved[0] == literal()


# -- reconcile ---------------------------------------------------------------


def test_reconcile_pushes_a_literal_without_touching_sops() -> None:
    client = RecordingClient({"bitcoin-nodes": "p1"})
    summary = reconcile(
        client, [literal()], organization_id="org", prune=False, dry_run=False
    )
    assert summary.ok
    assert summary.secrets_created == 1
    assert client.upserts == [
        {
            "name": "BITCOIND_RPC_PORT",
            "project_id": "p1",
            "environment": "mainnet",
            "secret_path": "/bitcoind",
            "value": "8332",
        }
    ]
    literal_actions = [a for a in summary.actions if a.kind == "secret"]
    assert literal_actions[0].result == "created"
    assert literal_actions[0].detail == "literal"


def test_dry_run_plans_a_literal_and_writes_nothing() -> None:
    client = RecordingClient({"bitcoin-nodes": "p1"})
    summary = reconcile(
        client, [literal()], organization_id="org", prune=False, dry_run=True
    )
    assert summary.ok
    assert client.upserts == []
    assert summary.secrets_planned == 1
    planned = [a for a in summary.actions if a.kind == "secret"]
    assert planned[0].result == "would-upsert"
    assert planned[0].detail == "literal"


def test_a_literal_in_a_project_that_does_not_exist_yet_is_skipped_not_failed() -> None:
    # Only reachable in a dry run against an unsynced instance -- but the
    # report must say "would-upsert", not "error", or the first dry run of a
    # fresh estate reads as broken.
    client = RecordingClient({})
    summary = reconcile(
        client, [literal()], organization_id="org", prune=False, dry_run=True
    )
    assert summary.ok
    assert client.upserts == []
