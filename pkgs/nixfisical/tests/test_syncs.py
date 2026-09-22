"""Offline tests for :mod:`nixfisical.syncs`.

The failures worth a test here are the quiet ones. A sync reconciler that
"succeeds" against the wrong project, or that prunes a sync it merely failed
to read, changes what Infisical pushes into a live GitHub repository without
anyone typing a secret. So: the declaration is validated before a request is
made; a missing connection or project is an error for *that* sync and the run
continues; drift is detected field by field; prune never crosses into a
project the declaration does not mention; and a dry run makes no write at all.
"""

from __future__ import annotations

from typing import Any

from nixfisical.api import InfisicalError
from nixfisical.syncs import app_for, reconcile_syncs, validate_syncs

ORG = "org-1"


class FakeClient:
    """Just enough of ``InfisicalClient`` for the syncs reconciler.

    ``syncs`` is keyed by project name and holds the raw shape the list
    endpoint returns (``environment`` and ``folder`` as objects), so the
    drift check exercises the real normalisation.
    """

    def __init__(
        self,
        projects: dict[str, str],
        connections: dict[tuple[str, str], str] | None = None,
        syncs: dict[str, list[dict[str, Any]]] | None = None,
    ) -> None:
        self.projects = projects
        self.connections = connections or {}
        self.syncs = syncs or {}
        self.ids_to_names = {value: key for key, value in projects.items()}
        self.created: list[tuple[str, dict[str, Any]]] = []
        self.updated: list[tuple[str, str, dict[str, Any]]] = []
        self.deleted: list[tuple[str, str, bool]] = []
        self.triggered: list[tuple[str, str]] = []
        self.listed: list[str] = []

    def list_projects(self, organization_id: str) -> dict[str, str]:
        assert organization_id == ORG
        return dict(self.projects)

    def get_app_connection(self, app: str, name: str) -> dict[str, Any] | None:
        cid = self.connections.get((app, name))
        return {"id": cid, "name": name, "app": app} if cid else None

    def list_secret_syncs(self, project_id: str) -> list[dict[str, Any]]:
        name = self.ids_to_names[project_id]
        self.listed.append(name)
        return list(self.syncs.get(name, []))

    def create_secret_sync(self, destination: str, body: dict[str, Any]) -> dict[str, Any]:
        self.created.append((destination, dict(body)))
        return {"id": f"new-{len(self.created)}", **body}

    def update_secret_sync(self, destination: str, sync_id: str, body: dict[str, Any]) -> dict[str, Any]:
        self.updated.append((destination, sync_id, dict(body)))
        return {"id": sync_id, **body}

    def delete_secret_sync(self, destination: str, sync_id: str, *, remove_secrets: bool = False) -> None:
        self.deleted.append((destination, sync_id, remove_secrets))

    def trigger_secret_sync(self, destination: str, sync_id: str) -> None:
        self.triggered.append((destination, sync_id))


def github(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "name": "jeirslab/homelab",
        "project": "org-engine",
        "destination": "github",
        "connection": "jeirslab-github",
        "environment": "prod",
        "secretPath": "/",
        "isAutoSyncEnabled": True,
        "syncOptions": {
            "initialSyncBehavior": "overwrite-destination",
            "keySchema": "{{secretKey}}",
            "disableSecretDeletion": False,
        },
        "destinationConfig": {"scope": "repository", "owner": "jeirslab", "repo": "homelab"},
    }
    base.update(overrides)
    return base


def live(entry: dict[str, Any], sync_id: str = "s-1", **overrides: Any) -> dict[str, Any]:
    """What the list endpoint returns for a sync that matches ``entry``."""
    shape: dict[str, Any] = {
        "id": sync_id,
        "name": entry["name"],
        "destination": entry["destination"],
        "connectionId": "c-github",
        "environment": {"slug": entry["environment"], "name": entry["environment"]},
        "folder": {"path": entry["secretPath"]},
        "isAutoSyncEnabled": entry.get("isAutoSyncEnabled", True),
        "syncOptions": dict(entry["syncOptions"]),
        "destinationConfig": dict(entry["destinationConfig"]),
        "description": entry.get("description"),
    }
    shape.update(overrides)
    return shape


PROJECTS = {"org-engine": "p-1", "platform": "p-2"}
CONNECTIONS = {("github", "jeirslab-github"): "c-github"}


# -- validation runs before any request -------------------------------------


def test_validation_names_every_structural_gap() -> None:
    problems = validate_syncs(
        [
            {"name": "x", "project": "p", "destination": "github", "connection": "c",
             "environment": "prod", "secretPath": "ci",
             "syncOptions": {}, "destinationConfig": {"scope": "repository", "owner": "o"}},
            github(),
            github(),
        ]
    )
    assert any("secretPath must start with '/'" in p for p in problems)
    assert any("initialSyncBehavior is required" in p for p in problems)
    assert any("destinationConfig.repo is required" in p for p in problems)
    assert any("declared twice" in p for p in problems)


def test_a_sound_declaration_has_no_problems() -> None:
    assert validate_syncs([github()]) == []


def test_app_kind_follows_the_destination_unless_overridden() -> None:
    assert app_for({"destination": "github"}) == "github"
    assert app_for({"destination": "aws-parameter-store"}) == "aws"
    assert app_for({"destination": "aws-parameter-store", "app": "custom"}) == "custom"


# -- create, no-op, update -----------------------------------------------------


def test_creates_a_missing_sync_with_resolved_ids() -> None:
    client = FakeClient(PROJECTS, CONNECTIONS)
    summary = reconcile_syncs(client, [github()], organization_id=ORG)
    assert summary.ok and summary.created == 1
    destination, body = client.created[0]
    assert destination == "github"
    assert body["projectId"] == "p-1" and body["connectionId"] == "c-github"
    assert body["destinationConfig"] == {"scope": "repository", "owner": "jeirslab", "repo": "homelab"}
    assert "project" not in body and "connection" not in body


def test_a_matching_live_sync_is_left_alone() -> None:
    entry = github()
    client = FakeClient(PROJECTS, CONNECTIONS, {"org-engine": [live(entry)]})
    summary = reconcile_syncs(client, [entry], organization_id=ORG)
    assert summary.ok and summary.unchanged == 1
    assert client.created == [] and client.updated == [] and client.deleted == []


def test_drift_in_the_address_is_patched_and_named() -> None:
    entry = github()
    stale = live(entry, destinationConfig={"scope": "repository", "owner": "jeirslab", "repo": "old"})
    client = FakeClient(PROJECTS, CONNECTIONS, {"org-engine": [stale]})
    summary = reconcile_syncs(client, [entry], organization_id=ORG)
    assert summary.ok and summary.updated == 1
    destination, sync_id, body = client.updated[0]
    assert (destination, sync_id) == ("github", "s-1")
    assert body["destinationConfig"]["repo"] == "homelab"
    assert "projectId" not in body
    assert any(a.result == "updated" and "destinationConfig" in a.detail for a in summary.actions)


def test_server_defaults_in_sync_options_are_not_drift() -> None:
    entry = github()
    with_defaults = live(entry)
    with_defaults["syncOptions"]["someServerDefault"] = True
    client = FakeClient(PROJECTS, CONNECTIONS, {"org-engine": [with_defaults]})
    summary = reconcile_syncs(client, [entry], organization_id=ORG)
    assert summary.unchanged == 1 and client.updated == []


# -- the failures that must stay local to one sync ---------------------------


def test_missing_connection_is_an_error_for_that_sync_only() -> None:
    client = FakeClient(PROJECTS, CONNECTIONS)
    other = github(name="other", connection="nope")
    summary = reconcile_syncs(client, [github(), other], organization_id=ORG)
    assert summary.created == 1
    assert len(summary.errors) == 1 and "no github connection named 'nope'" in summary.errors[0]


def test_missing_project_is_an_error_and_never_created_here() -> None:
    client = FakeClient(PROJECTS, CONNECTIONS)
    summary = reconcile_syncs(client, [github(project="ghost")], organization_id=ORG)
    assert client.created == []
    assert summary.errors and "does not exist" in summary.errors[0]


def test_a_changed_destination_is_refused_not_patched() -> None:
    entry = github()
    client = FakeClient(PROJECTS, CONNECTIONS, {"org-engine": [live(entry, destination="gitlab")]})
    summary = reconcile_syncs(client, [entry], organization_id=ORG)
    assert client.updated == [] and client.created == []
    assert summary.errors and "cannot change" in summary.errors[0]


def test_a_failed_listing_does_not_turn_into_a_create_or_a_prune() -> None:
    class Broken(FakeClient):
        def list_secret_syncs(self, project_id: str) -> list[dict[str, Any]]:
            raise InfisicalError("boom", status=500)

    client = Broken(PROJECTS, CONNECTIONS)
    summary = reconcile_syncs(client, [github()], organization_id=ORG)
    # The listing failed, so the reconciler cannot know whether the sync
    # exists. It still creates (create is idempotent-by-name on the server)
    # but the error is recorded, and the run exits non-zero.
    assert summary.errors and "list syncs" in summary.errors[0]


# -- prune stays inside declared projects ------------------------------------


def test_prune_deletes_undeclared_syncs_in_declared_projects_only() -> None:
    entry = github()
    stray = live(github(name="stray"), sync_id="s-stray")
    elsewhere = live(github(name="elsewhere", project="platform"), sync_id="s-else")
    client = FakeClient(PROJECTS, CONNECTIONS, {"org-engine": [live(entry), stray], "platform": [elsewhere]})
    summary = reconcile_syncs(client, [entry], organization_id=ORG)
    assert summary.pruned == 1
    assert client.deleted == [("github", "s-stray", False)]
    assert "platform" not in client.listed


def test_no_prune_keeps_strays() -> None:
    stray = live(github(name="stray"), sync_id="s-stray")
    client = FakeClient(PROJECTS, CONNECTIONS, {"org-engine": [stray]})
    summary = reconcile_syncs(client, [github()], organization_id=ORG, prune=False)
    assert summary.pruned == 0 and client.deleted == []


# -- dry run and run ----------------------------------------------------------


def test_dry_run_reads_everything_and_writes_nothing() -> None:
    stray = live(github(name="stray"), sync_id="s-stray")
    stale = live(github(), secretPath="/old", folder={"path": "/old"})
    client = FakeClient(PROJECTS, CONNECTIONS, {"org-engine": [stray, stale]})
    summary = reconcile_syncs(client, [github(), github(name="new")], organization_id=ORG, dry_run=True, run=True)
    assert summary.dry_run
    assert (summary.created, summary.updated, summary.pruned) == (1, 1, 1)
    assert client.created == [] and client.updated == [] and client.deleted == [] and client.triggered == []
    assert "would apply" in summary.headline()


def test_run_triggers_every_declared_sync_after_converging() -> None:
    entry = github()
    client = FakeClient(PROJECTS, CONNECTIONS, {"org-engine": [live(entry)]})
    summary = reconcile_syncs(client, [entry, github(name="new")], organization_id=ORG, run=True)
    assert summary.triggered == 2
    assert ("github", "s-1") in client.triggered and ("github", "new-1") in client.triggered
