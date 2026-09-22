"""Make the instance's secret syncs match the declaration.

A secret sync is Infisical pushing one folder of one environment of one
project onward -- into GitHub Actions secrets, Parameter Store, another
Infisical -- on its own schedule. ``sync`` pushes SOPS *into* Infisical; this
is the step after it, and it runs after it, because a sync whose project does
not exist yet cannot be created.

The declaration is a list of entries in the API's own vocabulary (ADR: bare
wire names, so every field is greppable against ``docs/openapi.json``) with
two substitutions the reconciler makes: ``project`` is a name and becomes
``projectId``; ``connection`` is a name and becomes ``connectionId``. A
connection is never created here. Authorising one is a browser round-trip
with the provider, which no reconciler should own; a declared connection that
does not exist is an error for that sync and the run continues.

Pruning is per project: a sync that exists in a *declared* project and is not
declared is deleted. Projects the declaration never mentions are not
touched, so an estate can adopt this one project at a time. Deleting a sync
never removes what it wrote downstream (``removeSecrets=false``): a mistaken
prune should cost a re-create, not a wiped GitHub repository.

Dry run lists projects, syncs and connections and writes nothing. Nothing
here prints a secret value; a sync body carries none.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from nixfisical.api import InfisicalClient, InfisicalError

__all__ = [
    "DESTINATION_APP",
    "SyncAction",
    "SyncsSummary",
    "app_for",
    "reconcile_syncs",
    "validate_syncs",
]

# Destination slug -> app-connection kind, where the two differ. A destination
# absent here uses its own slug as the app kind, which is true for github,
# gitlab, vercel and most of the rest.
DESTINATION_APP: dict[str, str] = {
    "aws-parameter-store": "aws",
    "aws-secrets-manager": "aws",
    "azure-app-configuration": "azure-app-configuration",
    "azure-key-vault": "azure-key-vault",
    "gcp-secret-manager": "gcp",
    "external-infisical": "infisical",
}

# The fields a PATCH may carry, in the API's order. ``projectId`` and the
# destination are fixed at creation; a declaration that changes either is a
# different sync, and the reconciler says so rather than guessing.
_MUTABLE = (
    "name",
    "description",
    "connectionId",
    "environment",
    "secretPath",
    "isAutoSyncEnabled",
    "syncOptions",
    "destinationConfig",
)


def app_for(entry: dict[str, Any]) -> str:
    """The app-connection kind a sync entry's connection is looked up under."""
    explicit = entry.get("app")
    if isinstance(explicit, str) and explicit:
        return explicit
    destination = str(entry.get("destination", ""))
    return DESTINATION_APP.get(destination, destination)


def validate_syncs(entries: Iterable[dict[str, Any]]) -> list[str]:
    """Structural problems, one line each; empty means the declaration is sound.

    Mirrors ``assertManifest`` on the Nix side so a hand-written JSON manifest
    gets the same checks a generated one already passed.
    """
    problems: list[str] = []
    seen: set[tuple[str, str]] = set()
    for index, entry in enumerate(entries):
        where = f"syncs[{index}]"
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            problems.append(f"{where}: missing name")
            name = f"<{index}>"
        where = f"sync {name!r}"
        for key in ("project", "destination", "connection", "environment", "secretPath"):
            value = entry.get(key)
            if not isinstance(value, str) or not value:
                problems.append(f"{where}: missing {key}")
        path = entry.get("secretPath")
        if isinstance(path, str) and path and not path.startswith("/"):
            problems.append(f"{where}: secretPath must start with '/': {path!r}")
        options = entry.get("syncOptions")
        if not isinstance(options, dict):
            problems.append(f"{where}: syncOptions must be an object")
        elif not options.get("initialSyncBehavior"):
            problems.append(f"{where}: syncOptions.initialSyncBehavior is required")
        config = entry.get("destinationConfig")
        if not isinstance(config, dict):
            problems.append(f"{where}: destinationConfig must be an object (use {{}} when empty)")
        elif entry.get("destination") == "github":
            scope = config.get("scope")
            need = {
                "organization": ("org", "visibility"),
                "repository": ("owner", "repo"),
                "repository-environment": ("owner", "repo", "env"),
            }.get(str(scope))
            if need is None:
                problems.append(
                    f"{where}: github destinationConfig.scope must be organization, "
                    f"repository or repository-environment, not {scope!r}"
                )
            else:
                for key in need:
                    if not config.get(key):
                        problems.append(f"{where}: github destinationConfig.{key} is required for scope {scope!r}")
        project = entry.get("project")
        if isinstance(project, str) and isinstance(name, str):
            coordinate = (project, name)
            if coordinate in seen:
                problems.append(f"{where}: declared twice in project {project!r}")
            seen.add(coordinate)
    return problems


@dataclass(frozen=True)
class SyncAction:
    """One thing the reconciler did, or would have done in a dry run."""

    target: str
    result: str
    detail: str = ""

    def render(self) -> str:
        line = f"{self.result:<14} sync        {self.target}"
        return f"{line}  -- {self.detail}" if self.detail else line


@dataclass
class SyncsSummary:
    dry_run: bool = False
    prune: bool = False
    created: int = 0
    updated: int = 0
    unchanged: int = 0
    pruned: int = 0
    triggered: int = 0
    errors: list[str] = field(default_factory=list)
    actions: list[SyncAction] = field(default_factory=list)

    def record(self, target: str, result: str, detail: str = "") -> None:
        self.actions.append(SyncAction(target=target, result=result, detail=detail))

    def fail(self, target: str, detail: str) -> None:
        self.errors.append(f"sync {target}: {detail}")
        self.record(target, "error", detail)

    @property
    def ok(self) -> bool:
        return not self.errors

    def headline(self) -> str:
        verb = "would apply" if self.dry_run else "applied"
        run = f", triggered {self.triggered}" if self.triggered else ""
        return (
            f"{verb}: syncs +{self.created}/~{self.updated}/={self.unchanged}, "
            f"pruned -{self.pruned}{run}, errors {len(self.errors)}"
        )


def _coordinate(entry: dict[str, Any]) -> str:
    return f"{entry.get('project')}:{entry.get('name')} -> {entry.get('destination')}"


def _slug(value: Any) -> Any:
    """An environment the API returns as an object, or the slug we sent."""
    if isinstance(value, dict):
        return value.get("slug")
    return value


def _path(existing: dict[str, Any]) -> Any:
    folder = existing.get("folder")
    if isinstance(folder, dict):
        return folder.get("path")
    return existing.get("secretPath")


def _desired_body(entry: dict[str, Any], *, project_id: str, connection_id: str) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": entry["name"],
        "projectId": project_id,
        "connectionId": connection_id,
        "environment": entry["environment"],
        "secretPath": entry["secretPath"],
        "isAutoSyncEnabled": bool(entry.get("isAutoSyncEnabled", True)),
        "syncOptions": dict(entry.get("syncOptions") or {}),
        "destinationConfig": dict(entry.get("destinationConfig") or {}),
    }
    description = entry.get("description")
    if isinstance(description, str) and description:
        body["description"] = description
    return body


def _drift(existing: dict[str, Any], desired: dict[str, Any]) -> list[str]:
    """Field names whose live value differs from the declaration.

    ``syncOptions`` is compared key by key over the declared keys only: the
    server fills defaults we never wrote, and a default is not drift.
    ``destinationConfig`` is compared whole, because for every destination it
    is the address, and a partial address is a different place.
    """
    changed: list[str] = []
    if existing.get("name") != desired["name"]:
        changed.append("name")
    if (existing.get("description") or "") != desired.get("description", ""):
        changed.append("description")
    if existing.get("connectionId") != desired["connectionId"]:
        changed.append("connectionId")
    if _slug(existing.get("environment")) != desired["environment"]:
        changed.append("environment")
    if _path(existing) != desired["secretPath"]:
        changed.append("secretPath")
    if bool(existing.get("isAutoSyncEnabled", True)) != desired["isAutoSyncEnabled"]:
        changed.append("isAutoSyncEnabled")
    live_options = existing.get("syncOptions") or {}
    for key, value in desired["syncOptions"].items():
        if live_options.get(key) != value:
            changed.append(f"syncOptions.{key}")
    if (existing.get("destinationConfig") or {}) != desired["destinationConfig"]:
        changed.append("destinationConfig")
    return changed


def reconcile_syncs(
    client: InfisicalClient,
    entries: Iterable[dict[str, Any]],
    *,
    organization_id: str,
    prune: bool = True,
    dry_run: bool = False,
    run: bool = False,
) -> SyncsSummary:
    """Converge the instance's secret syncs onto ``entries``.

    ``run`` triggers every declared sync after it is converged (creation
    already starts one server-side when auto-sync is on; this is for the
    first run against a destination and for forcing a re-push).
    """
    declared = list(entries)
    summary = SyncsSummary(dry_run=dry_run, prune=prune)

    try:
        projects = client.list_projects(organization_id)
    except InfisicalError as exc:
        summary.errors.append(f"list projects: {exc}")
        return summary

    connections: dict[tuple[str, str], str | None] = {}

    def connection_id(entry: dict[str, Any]) -> str | None:
        key = (app_for(entry), str(entry["connection"]))
        if key not in connections:
            try:
                found = client.get_app_connection(*key)
            except InfisicalError as exc:
                summary.fail(_coordinate(entry), f"look up connection {key[1]!r}: {exc}")
                connections[key] = None
                return None
            connections[key] = str(found["id"]) if found and found.get("id") else None
        return connections[key]

    # Live syncs per declared project, fetched once. A project that does not
    # exist is an error for every sync in it: `sync` creates projects, this
    # command does not, and the two run in that order for exactly this reason.
    live: dict[str, dict[str, dict[str, Any]]] = {}
    for project in sorted({str(e.get("project")) for e in declared}):
        project_id = projects.get(project)
        if not project_id:
            live[project] = {}
            continue
        try:
            live[project] = {
                str(s.get("name")): s for s in client.list_secret_syncs(project_id)
            }
        except InfisicalError as exc:
            summary.errors.append(f"list syncs in {project!r}: {exc}")
            live[project] = {}

    kept: dict[str, set[str]] = {project: set() for project in live}
    to_trigger: list[tuple[str, str, str]] = []

    for entry in declared:
        target = _coordinate(entry)
        project = str(entry["project"])
        project_id = projects.get(project)
        if not project_id:
            summary.fail(target, f"project {project!r} does not exist (run 'nixfisical sync' first)")
            continue
        cid = connection_id(entry)
        if cid is None:
            if not any(err.startswith(f"sync {target}:") for err in summary.errors):
                summary.fail(
                    target,
                    f"no {app_for(entry)} connection named {entry['connection']!r}; "
                    "authorise one in the UI (App Connections) with that name",
                )
            continue
        destination = str(entry["destination"])
        desired = _desired_body(entry, project_id=project_id, connection_id=cid)
        kept[project].add(desired["name"])
        existing = live.get(project, {}).get(desired["name"])

        if existing is None:
            if dry_run:
                summary.created += 1
                summary.record(target, "would-create")
                continue
            try:
                created = client.create_secret_sync(destination, desired)
            except InfisicalError as exc:
                summary.fail(target, f"create: {exc}")
                continue
            summary.created += 1
            summary.record(target, "created")
            if run and created.get("id"):
                to_trigger.append((target, destination, str(created["id"])))
            continue

        if existing.get("destination") not in (None, destination):
            summary.fail(
                target,
                f"exists with destination {existing.get('destination')!r}; a destination "
                "cannot change -- remove the declaration, let prune delete it, then re-declare",
            )
            continue

        changed = _drift(existing, desired)
        sync_id = str(existing.get("id", ""))
        if not changed:
            summary.unchanged += 1
            summary.record(target, "exists")
        elif dry_run:
            summary.updated += 1
            summary.record(target, "would-update", ", ".join(changed))
        else:
            patch = {key: desired[key] for key in _MUTABLE if key in desired}
            try:
                client.update_secret_sync(destination, sync_id, patch)
            except InfisicalError as exc:
                summary.fail(target, f"update: {exc}")
                continue
            summary.updated += 1
            summary.record(target, "updated", ", ".join(changed))
        if run and sync_id:
            to_trigger.append((target, destination, sync_id))

    if prune:
        for project, syncs in live.items():
            for name, existing in sorted(syncs.items()):
                if name in kept[project]:
                    continue
                target = f"{project}:{name} -> {existing.get('destination')}"
                if dry_run:
                    summary.pruned += 1
                    summary.record(target, "would-delete", "not declared")
                    continue
                try:
                    client.delete_secret_sync(
                        str(existing.get("destination")), str(existing.get("id")), remove_secrets=False
                    )
                except InfisicalError as exc:
                    summary.fail(target, f"delete: {exc}")
                    continue
                summary.pruned += 1
                summary.record(target, "deleted", "not declared; downstream secrets left in place")

    for target, destination, sync_id in to_trigger:
        if dry_run:
            summary.triggered += 1
            summary.record(target, "would-trigger")
            continue
        try:
            client.trigger_secret_sync(destination, sync_id)
        except InfisicalError as exc:
            summary.fail(target, f"trigger: {exc}")
            continue
        summary.triggered += 1
        summary.record(target, "triggered")

    return summary
