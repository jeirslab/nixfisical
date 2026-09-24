"""Offline tests for ``--prune-environments`` and project descriptions.

Both touch things the manifest does not itself describe, so the failures
worth pinning are the ones where the reconciler acts on more than it knows:

* **An undeclared environment that holds a secret is never deleted.** The
  secret prune only ever lists declared environments, so the contents of an
  undeclared one are unknown to this run -- deleting it would be the one
  destructive act in ``sync`` with no dry-run line naming each casualty.
* **An empty undeclared environment is deleted, and only with the flag.**
  Without ``prune_environments`` the reconciler must not even look.
* **Dry run makes no write**, for environments as for everything else.
* **New projects are created without Infisical's default environments**,
  and with the declared description, so the seeding problem does not recur.
* **A description is reconciled, not just set on create**, and an absent
  ``description`` key leaves the instance's text alone.
"""

from __future__ import annotations

from typing import Any

from nixfisical.reconcile import reconcile, validate_projects


def entry(project: str = "p", environment: str = "prod", name: str = "X") -> dict[str, Any]:
    return {
        "sopsKey": f"literal:{project}/{environment}/:{name}",
        "sopsFile": None,
        "project": project,
        "environment": environment,
        "folder": "/",
        "name": name,
        "value": "v",
        "groups": [],
        "hosts": [],
        "source": "literal",
    }


class FakeClient:
    """Projects with environments and per-environment secret lists."""

    def __init__(
        self,
        projects: dict[str, str],
        environments: dict[str, list[dict[str, str]]] | None = None,
        secrets: dict[tuple[str, str], list[dict[str, Any]]] | None = None,
        descriptions: dict[str, str] | None = None,
    ) -> None:
        self.projects = projects
        self.environments = environments or {}
        self.secrets = secrets or {}
        self.descriptions = descriptions or {}
        self.ids_to_names = {v: k for k, v in projects.items()}
        self.created: list[tuple[str, dict[str, Any]]] = []
        self.deleted_environments: list[tuple[str, str]] = []
        self.updated_descriptions: list[tuple[str, str]] = []
        self.upserts = 0

    def list_projects(self, organization_id: str) -> dict[str, str]:
        return dict(self.projects)

    def create_project(self, name: str, **kwargs: Any) -> str:
        self.created.append((name, kwargs))
        pid = f"id-{name}"
        self.projects[name] = pid
        self.ids_to_names[pid] = name
        return pid

    def get_project(self, project_id: str) -> dict[str, Any]:
        name = self.ids_to_names[project_id]
        return {
            "id": project_id,
            "name": name,
            "description": self.descriptions.get(name, ""),
            "environments": list(self.environments.get(name, [])),
        }

    def update_project(self, project_id: str, *, description: str) -> None:
        self.updated_descriptions.append((self.ids_to_names[project_id], description))

    def create_environment(self, project_id: str, *, name: str, slug: str) -> bool:
        return False

    def create_folder(self, *, project_id: str, environment: str, path: str, name: str) -> bool:
        return False

    def upsert_secret(self, name: str, **kwargs: Any) -> str:
        self.upserts += 1
        return "created"

    def list_secrets(self, *, project_id: str, environment: str, path: str = "/") -> list[dict[str, Any]]:
        return list(self.secrets.get((self.ids_to_names[project_id], environment), []))

    def delete_environment(self, project_id: str, environment_id: str) -> None:
        self.deleted_environments.append((self.ids_to_names[project_id], environment_id))


DEFAULT_TRIO = [
    {"id": "e-dev", "name": "Development", "slug": "dev"},
    {"id": "e-staging", "name": "Staging", "slug": "staging"},
    {"id": "e-prod", "name": "Production", "slug": "prod"},
]


# -- pruning -------------------------------------------------------------------


def test_without_the_flag_no_environment_is_touched_or_even_listed() -> None:
    client = FakeClient({"p": "p1"}, {"p": DEFAULT_TRIO})
    summary = reconcile(client, [entry()], organization_id="org", prune=False)
    assert summary.ok
    assert client.deleted_environments == []
    assert not any(a.kind == "prune-env" for a in summary.actions)


def test_empty_undeclared_environments_are_deleted_declared_ones_kept() -> None:
    client = FakeClient({"p": "p1"}, {"p": DEFAULT_TRIO})
    summary = reconcile(
        client, [entry(environment="prod")], organization_id="org", prune=False,
        prune_environments=True,
    )
    assert summary.ok
    assert sorted(client.deleted_environments) == [("p", "e-dev"), ("p", "e-staging")]
    assert summary.environments_pruned == 2
    assert summary.environments_kept == 0
    assert "environments -2" in summary.headline()


def test_a_non_empty_undeclared_environment_is_kept_and_named() -> None:
    client = FakeClient(
        {"p": "p1"},
        {"p": DEFAULT_TRIO},
        secrets={("p", "staging"): [{"secretKey": "LEFTOVER", "secretPath": "/"}]},
    )
    summary = reconcile(
        client, [entry(environment="prod")], organization_id="org", prune=False,
        prune_environments=True,
    )
    assert summary.ok
    assert client.deleted_environments == [("p", "e-dev")]
    assert summary.environments_kept == 1
    kept = [a for a in summary.actions if a.kind == "prune-env" and a.result == "kept"]
    assert kept and kept[0].target == "p/staging" and "1 secret" in kept[0].detail
    assert "kept 1 non-empty" in summary.headline()


def test_dry_run_reports_environment_deletions_and_writes_nothing() -> None:
    client = FakeClient({"p": "p1"}, {"p": DEFAULT_TRIO})
    summary = reconcile(
        client, [entry(environment="prod")], organization_id="org", prune=False,
        prune_environments=True, dry_run=True,
    )
    assert summary.ok
    assert client.deleted_environments == []
    assert client.upserts == 0
    assert summary.environments_pruned == 2
    assert [a.result for a in summary.actions if a.kind == "prune-env"] == ["would-delete", "would-delete"]


def test_pruning_stays_inside_declared_projects() -> None:
    # `other` exists on the instance with the default trio but the manifest
    # never mentions it -- nothing in it may be touched.
    client = FakeClient({"p": "p1", "other": "p2"}, {"p": DEFAULT_TRIO, "other": DEFAULT_TRIO})
    reconcile(
        client, [entry(environment="prod")], organization_id="org", prune=False,
        prune_environments=True,
    )
    assert all(project == "p" for project, _ in client.deleted_environments)


# -- projects ----------------------------------------------------------------


def test_new_projects_get_no_default_environments_and_the_declared_description() -> None:
    client = FakeClient({})
    summary = reconcile(
        client, [entry(project="new")], organization_id="org", prune=False,
        projects={"new": {"description": "Fresh"}},
    )
    assert summary.ok
    assert client.created == [("new", {"description": "Fresh"})]
    created = [a for a in summary.actions if a.kind == "project" and a.result == "created"]
    assert created[0].detail == "with description"


def test_description_is_reconciled_on_an_existing_project() -> None:
    client = FakeClient({"p": "p1"}, descriptions={"p": "old text"})
    summary = reconcile(
        client, [entry()], organization_id="org", prune=False,
        projects={"p": {"description": "new text"}},
    )
    assert summary.ok
    assert client.updated_descriptions == [("p", "new text")]
    assert summary.projects_described == 1


def test_matching_description_is_not_rewritten_and_absent_key_is_left_alone() -> None:
    client = FakeClient({"p": "p1", "q": "q1"}, descriptions={"p": "same", "q": "theirs"})
    summary = reconcile(
        client, [entry(project="p"), entry(project="q")], organization_id="org", prune=False,
        projects={"p": {"description": "same"}, "q": {}},
    )
    assert summary.ok
    assert client.updated_descriptions == []
    assert summary.projects_described == 0


def test_dry_run_reports_a_description_change_without_writing() -> None:
    client = FakeClient({"p": "p1"}, descriptions={"p": "old"})
    summary = reconcile(
        client, [entry()], organization_id="org", prune=False, dry_run=True,
        projects={"p": {"description": "new"}},
    )
    assert client.updated_descriptions == []
    assert [a.result for a in summary.actions if a.kind == "project"] == ["exists", "would-update"]


def test_projects_file_validation() -> None:
    assert validate_projects({"p": {"description": "ok"}}) == []
    assert validate_projects({"p": {}}) == []
    assert any("unknown field" in p for p in validate_projects({"p": {"colour": "red"}}))
    assert any("must be a string" in p for p in validate_projects({"p": {"description": 3}}))
    assert any("1024" in p for p in validate_projects({"p": {"description": "x" * 1025}}))
    assert any("must be an object" in p for p in validate_projects({"p": "text"}))
