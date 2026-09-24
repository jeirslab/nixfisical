"""Make a remote Infisical instance match the declarative manifest.

The order below is not cosmetic -- each step is a precondition for the next.
Projects must exist before environments; environments before folders; folders
before the secrets that live in them. Pruning goes last so that a run which
fails partway through has still converged everything it managed to write, and
has deleted nothing on the strength of an incomplete picture.

Failure policy: an individual secret that cannot be resolved or written records
an error and the run continues. One rotated-away SOPS key should not block the
other forty-nine secrets in the estate from converging. The caller (``cli``)
exits non-zero if any error was recorded.

Dry run performs every read -- project list, secret list -- and no write. It is
the safety net that answers "what is this about to do to production?", so it
must be honest about prunes in particular: an unexpected deletion list is
usually a manifest-generation bug, and the dry run is where you find out.

Nothing here prints a secret value. Dry-run output names coordinates only:
project, environment, folder, secret name.

Three kinds of entry reach step 5, told apart by ``source``. A ``sops`` entry
is decrypted and pushed. An ``infisical`` entry is structure only -- its value
is the instance's, and ``pull`` is the command that reads it. A ``literal``
entry is pushed like a SOPS one but its value came in the manifest, so no file
is opened: it is the port or the hostname beside the password, not the
password.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

from nixfisical.api import InfisicalClient, InfisicalError
from nixfisical.manifest import LITERAL_SOURCE, entry_source
from nixfisical.sops import SopsError, read_key

__all__ = ["Action", "ReconcileSummary", "reconcile", "folder_ancestors", "validate_projects"]


@dataclass(frozen=True)
class Action:
    """One thing reconcile did, or would have done in a dry run.

    ``kind`` is the object type (``project``/``environment``/``folder``/
    ``secret``/``prune``), ``target`` its coordinate, ``result`` one of
    ``created``/``updated``/``exists``/``deleted``/``delegated``/``would-*``/
    ``skipped``/``error``.

    ``delegated`` is the one that means "correctly did nothing": the entry
    declares ``source = "infisical"``, so its value is not this command's to
    write. ``skipped``, by contrast, means something was in the way.
    """

    kind: str
    target: str
    result: str
    detail: str = ""

    def render(self) -> str:
        line = f"{self.result:<14} {self.kind:<11} {self.target}"
        return f"{line}  -- {self.detail}" if self.detail else line


@dataclass
class ReconcileSummary:
    """Counts and a per-action log for one reconcile run."""

    dry_run: bool = False
    prune: bool = False
    projects_created: int = 0
    environments_created: int = 0
    folders_created: int = 0
    secrets_created: int = 0
    secrets_updated: int = 0
    secrets_pruned: int = 0
    # Declared `source = "infisical"`: structure reconciled, value left to the
    # instance. Counted separately and never folded into created/updated,
    # because "sync touched 40 secrets" and "sync touched 31 and deliberately
    # did not touch 9" are different reports.
    secrets_delegated: int = 0
    # `--prune-environments`: undeclared environments in declared projects.
    # Deleted only when empty; a non-empty one is kept and counted, because
    # the manifest never described its contents and deleting them on the
    # strength of that would be the one destructive act here without a
    # dry-run line that names each casualty.
    environments_pruned: int = 0
    environments_kept: int = 0
    # Project descriptions reconciled from the projects file.
    projects_described: int = 0
    groups_seen: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    actions: list[Action] = field(default_factory=list)

    # Writes a dry run would attempt but cannot classify as create-vs-no-op.
    #
    # A dry run lists projects and it lists live secrets for the prune pass, so
    # `projects_created` and `secrets_pruned` are exact. It does NOT list
    # environments, folders, or secret values -- ensure/upsert are idempotent
    # server-side and the run is cheaper for not asking. The cost of not asking
    # is that "would create 5 folders" and "5 folders already match" are
    # indistinguishable from here, so these count *planned writes* and the
    # headline marks them `~` rather than folding them into the `+` counters and
    # claiming a precision this run does not have.
    environments_planned: int = 0
    folders_planned: int = 0
    secrets_planned: int = 0

    def record(self, kind: str, target: str, result: str, detail: str = "") -> None:
        self.actions.append(Action(kind=kind, target=target, result=result, detail=detail))

    def fail(self, kind: str, target: str, detail: str) -> None:
        self.errors.append(f"{kind} {target}: {detail}")
        self.record(kind, target, "error", detail)

    @property
    def ok(self) -> bool:
        return not self.errors

    @property
    def _delegated_clause(self) -> str:
        """``, delegated N`` -- or nothing at all when the estate has none.

        Suppressed at zero on purpose. Most fleets will never set
        `source = "infisical"`, and a counter that is always `0` teaches
        everyone reading the headline to stop reading it.
        """
        return f", delegated {self.secrets_delegated}" if self.secrets_delegated else ""

    @property
    def _env_prune_clause(self) -> str:
        """``, environments -N`` (plus ``/kept M``) -- only when pruning ran."""
        if not self.environments_pruned and not self.environments_kept:
            return ""
        kept = f" (kept {self.environments_kept} non-empty)" if self.environments_kept else ""
        return f", environments -{self.environments_pruned}{kept}"

    def headline(self) -> str:
        if self.dry_run:
            # `+` where the run knows, `~` where it would write without knowing
            # whether the write changes anything. Reporting the `~` figures as
            # `+0` -- which is what this did until the counters below existed --
            # renders a plan of nine writes as "nothing to do", and the headline
            # is the line an operator actually reads.
            return (
                f"would apply: projects +{self.projects_created}, "
                f"environments ~{self.environments_planned}, "
                f"folders ~{self.folders_planned}, "
                f"secrets ~{self.secrets_planned}, "
                f"pruned -{self.secrets_pruned}{self._env_prune_clause}{self._delegated_clause}, "
                f"errors {len(self.errors)}"
            )
        return (
            f"applied: projects +{self.projects_created}, "
            f"environments +{self.environments_created}, "
            f"folders +{self.folders_created}, "
            f"secrets +{self.secrets_created}/~{self.secrets_updated}, "
            f"pruned -{self.secrets_pruned}{self._env_prune_clause}{self._delegated_clause}, "
            f"errors {len(self.errors)}"
        )

    def legend(self) -> str:
        """One line explaining the dry-run headline's `~`. Empty when applied."""
        if not self.dry_run:
            return ""
        return (
            "  ~ = would be written; a dry run does not list environments, "
            "folders or secret values, so it cannot say which already match."
        )


def folder_ancestors(folder: str) -> list[tuple[str, str]]:
    """Expand ``/a/b/c`` into the ``(parent, leaf)`` pairs needed to create it.

    Returns ``[("/", "a"), ("/a", "b"), ("/a/b", "c")]``. The Infisical folder
    endpoint has no ``mkdir -p``: it takes a parent ``path`` that must already
    exist plus a leaf ``name``. The root ``/`` is not a folder anyone creates,
    so it never appears as a leaf.
    """
    segments = [segment for segment in folder.split("/") if segment]
    pairs: list[tuple[str, str]] = []
    parent = "/"
    for segment in segments:
        pairs.append((parent, segment))
        parent = f"{parent.rstrip('/')}/{segment}"
    return pairs


def _full_path(parent: str, leaf: str) -> str:
    return f"{parent.rstrip('/')}/{leaf}"


def _description_of(meta: Mapping[str, Any] | None) -> str | None:
    """The declared description, or None when the projects file has none.

    An empty string is a declaration ("no description") and is honoured;
    a missing key is not, so the instance's own text is left alone.
    """
    if meta is None or "description" not in meta:
        return None
    value = meta.get("description")
    return str(value) if value is not None else ""


def validate_projects(projects: Mapping[str, Any]) -> list[str]:
    """Structural problems in a projects file; empty means fine."""
    problems: list[str] = []
    if not isinstance(projects, Mapping):
        return ["projects must be an object keyed by project name"]
    for name, meta in projects.items():
        if not isinstance(name, str) or not name.strip():
            problems.append("projects: empty project name")
            continue
        if not isinstance(meta, Mapping):
            problems.append(f"projects[{name!r}]: must be an object")
            continue
        for key in meta:
            if key != "description":
                problems.append(f"projects[{name!r}]: unknown field {key!r} (only 'description')")
        description = meta.get("description")
        if description is not None and not isinstance(description, str):
            problems.append(f"projects[{name!r}]: description must be a string")
        elif isinstance(description, str) and len(description) > 1024:
            problems.append(f"projects[{name!r}]: description longer than 1024 characters")
    return problems


def _coordinate(entry: dict[str, Any]) -> str:
    """A printable coordinate for an entry. Never includes a value."""
    return (
        f"{entry.get('project')}/{entry.get('environment')}"
        f"{entry.get('folder')}:{entry.get('name')}"
    )


def reconcile(
    client: InfisicalClient,
    manifest: Iterable[dict[str, Any]],
    *,
    organization_id: str,
    prune: bool = True,
    dry_run: bool = False,
    prune_environments: bool = False,
    projects: Mapping[str, Mapping[str, Any]] | None = None,
) -> ReconcileSummary:
    """Converge the instance onto ``manifest``.

    ``organization_id`` scopes the project listing; it comes from the admin
    file written at bootstrap.

    ``projects`` is per-project metadata keyed by name -- today just
    ``description`` -- applied on create and reconciled on every run. A
    project the manifest names but ``projects`` does not is left as it is.

    ``prune_environments`` deletes environments the manifest does not declare
    in projects it does, but only EMPTY ones: the secret prune above never
    looked inside an undeclared environment, so anything in there is
    something this run knows nothing about. Non-empty ones are reported and
    kept; empty the environment (or declare it) and the next run removes it.
    """
    entries = list(manifest)
    summary = ReconcileSummary(dry_run=dry_run, prune=prune)
    project_meta: dict[str, Mapping[str, Any]] = dict(projects or {})

    groups: set[str] = set()
    for entry in entries:
        for group in entry.get("groups") or []:
            if isinstance(group, str):
                groups.add(group)
    summary.groups_seen = sorted(groups)

    # -- 1. existing projects ---------------------------------------------
    try:
        project_ids = client.list_projects(organization_id)
    except InfisicalError as exc:
        summary.fail("organization", organization_id, f"could not list projects: {exc}")
        return summary

    # -- 2. missing projects ----------------------------------------------
    wanted_projects = sorted({str(entry["project"]) for entry in entries if entry.get("project")})
    for name in wanted_projects:
        wanted_description = _description_of(project_meta.get(name))
        if name in project_ids:
            summary.record("project", name, "exists")
            if wanted_description is None:
                continue
            # Reconcile the description. One GET per declared project; the
            # listing endpoint does not return descriptions, so this is the
            # only way to know whether a PATCH would change anything.
            try:
                live = client.get_project(project_ids[name])
            except InfisicalError as exc:
                summary.fail("project", name, f"could not read project: {exc}")
                continue
            if (live.get("description") or "") == wanted_description:
                continue
            if dry_run:
                summary.projects_described += 1
                summary.record("project", name, "would-update", "description")
                continue
            try:
                client.update_project(project_ids[name], description=wanted_description)
            except InfisicalError as exc:
                summary.fail("project", name, f"update description: {exc}")
                continue
            summary.projects_described += 1
            summary.record("project", name, "updated", "description")
            continue
        if dry_run:
            summary.record("project", name, "would-create")
            summary.projects_created += 1
            continue
        try:
            project_ids[name] = client.create_project(name, description=wanted_description)
        except InfisicalError as exc:
            summary.fail("project", name, str(exc))
            continue
        summary.projects_created += 1
        summary.record(
            "project", name, "created", "with description" if wanted_description else ""
        )

    def resolve_project(entry: dict[str, Any]) -> str | None:
        """Project id for an entry, or None when it does not exist yet.

        In a dry run the project may legitimately not exist -- we did not
        create it. Downstream steps then log what they would do without an id,
        which is the honest thing to report.
        """
        return project_ids.get(str(entry.get("project")))

    # -- 3. environments ---------------------------------------------------
    env_pairs = sorted(
        {
            (str(entry["project"]), str(entry["environment"]))
            for entry in entries
            if entry.get("project") and entry.get("environment")
        }
    )
    for project_name, environment in env_pairs:
        target = f"{project_name}/{environment}"
        project_id = project_ids.get(project_name)
        if project_id is None:
            # Only reachable in a dry run, or after a project creation error.
            summary.record(
                "environment",
                target,
                "would-create" if dry_run else "skipped",
                "project does not exist yet",
            )
            if dry_run:
                summary.environments_planned += 1
            continue
        if dry_run:
            summary.environments_planned += 1
            summary.record("environment", target, "would-ensure")
            continue
        try:
            created = client.create_environment(
                project_id, name=environment, slug=environment
            )
        except InfisicalError as exc:
            summary.fail("environment", target, str(exc))
            continue
        if created:
            summary.environments_created += 1
        summary.record("environment", target, "created" if created else "exists")

    # -- 4. folders --------------------------------------------------------
    # Every ancestor of every declared folder, deduplicated, then sorted by
    # depth so a parent is always created before its children. Sorting by the
    # string alone is not enough: "/a/b" sorts before "/a" in no ordering we
    # want to depend on, and the API rejects a create whose parent is missing.
    folder_targets: set[tuple[str, str, str, str]] = set()
    for entry in entries:
        folder = str(entry.get("folder") or "/")
        if folder == "/":
            continue
        for parent, leaf in folder_ancestors(folder):
            folder_targets.add(
                (str(entry["project"]), str(entry["environment"]), parent, leaf)
            )

    for project_name, environment, parent, leaf in sorted(
        folder_targets, key=lambda item: (item[0], item[1], item[2].count("/"), item[2], item[3])
    ):
        target = f"{project_name}/{environment}{_full_path(parent, leaf)}"
        project_id = project_ids.get(project_name)
        if project_id is None:
            summary.record(
                "folder",
                target,
                "would-create" if dry_run else "skipped",
                "project does not exist yet",
            )
            if dry_run:
                summary.folders_planned += 1
            continue
        if dry_run:
            summary.folders_planned += 1
            summary.record("folder", target, "would-ensure")
            continue
        try:
            created = client.create_folder(
                project_id=project_id,
                environment=environment,
                path=parent,
                name=leaf,
            )
        except InfisicalError as exc:
            summary.fail("folder", target, str(exc))
            continue
        if created:
            summary.folders_created += 1
        summary.record("folder", target, "created" if created else "exists")

    # -- 5. secrets --------------------------------------------------------
    for entry in entries:
        target = _coordinate(entry)

        # An Infisical-owned secret gets its structure from this run and its
        # value from nobody. The folder above was created for it, the prune
        # pass below counts it as declared and so leaves it alone, and its
        # groups are in `groups_seen` for `sync-access` -- everything except
        # the one step that would overwrite the copy the instance owns.
        #
        # Its SOPS file is deliberately not opened, not even to check. A
        # freshly declared Infisical-owned secret has no SOPS key yet (that is
        # what `import` is for), and a `sync` that failed because the pull had
        # not run yet would make the two commands ordering-dependent in the
        # one direction that has no reason to be.
        if entry_source(entry) == "infisical":
            summary.secrets_delegated += 1
            summary.record(
                "secret", target, "delegated", "source=infisical; run 'import' to pull it"
            )
            continue

        # A literal's value is already in hand -- it came in the manifest, and
        # `validate` has already insisted it is a non-empty string. No SOPS
        # file is opened, which is the whole point: this is the configuration
        # that is not secret but that a rendered .env is useless without.
        if entry_source(entry) == LITERAL_SOURCE:
            project_id = resolve_project(entry)
            if project_id is None:
                summary.record(
                    "secret",
                    target,
                    "would-upsert" if dry_run else "skipped",
                    "project does not exist yet",
                )
                if dry_run:
                    summary.secrets_planned += 1
                continue
            if dry_run:
                summary.secrets_planned += 1
                summary.record("secret", target, "would-upsert", "literal")
                continue
            try:
                outcome = client.upsert_secret(
                    str(entry["name"]),
                    project_id=project_id,
                    environment=str(entry["environment"]),
                    secret_path=str(entry.get("folder") or "/"),
                    value=str(entry["value"]),
                )
            except InfisicalError as exc:
                summary.fail("secret", target, str(exc))
                continue
            if outcome == "created":
                summary.secrets_created += 1
            else:
                summary.secrets_updated += 1
            summary.record("secret", target, outcome, "literal")
            continue

        sops_file = entry.get("sopsFile")
        if not sops_file:
            summary.fail(
                "secret",
                target,
                f"no sopsFile for sopsKey {entry.get('sopsKey')!r} and no global default",
            )
            continue

        project_id = resolve_project(entry)
        if project_id is None:
            summary.record(
                "secret",
                target,
                "would-upsert" if dry_run else "skipped",
                "project does not exist yet",
            )
            if dry_run:
                summary.secrets_planned += 1
            continue

        if dry_run:
            # Still resolve the value: a dry run that does not touch SOPS would
            # miss the single most common failure (a renamed or rotated key),
            # which is exactly what the operator is dry-running to find out.
            # The value is read and immediately discarded; it is never logged.
            try:
                read_key(Path(sops_file), str(entry["sopsKey"]))
            except SopsError as exc:
                summary.fail("secret", target, str(exc))
                continue
            summary.secrets_planned += 1
            summary.record("secret", target, "would-upsert", f"from {sops_file}")
            continue

        try:
            value = read_key(Path(sops_file), str(entry["sopsKey"]))
        except SopsError as exc:
            summary.fail("secret", target, str(exc))
            continue

        try:
            outcome = client.upsert_secret(
                str(entry["name"]),
                project_id=project_id,
                environment=str(entry["environment"]),
                secret_path=str(entry.get("folder") or "/"),
                value=value,
            )
        except InfisicalError as exc:
            summary.fail("secret", target, str(exc))
            continue
        finally:
            del value  # bound the plaintext's lifetime in this frame

        if outcome == "created":
            summary.secrets_created += 1
        else:
            summary.secrets_updated += 1
        summary.record("secret", target, outcome)

    # -- 6. prune ----------------------------------------------------------
    # Folders are never pruned. An empty folder is harmless, whereas deleting
    # one would cascade over anything a human put there out-of-band, and the
    # manifest does not claim to describe folder existence -- only secrets.
    if prune:
        declared: set[tuple[str, str, str, str]] = {
            (
                str(entry.get("project")),
                str(entry.get("environment")),
                str(entry.get("folder") or "/"),
                str(entry.get("name")),
            )
            for entry in entries
        }
        for project_name, environment in env_pairs:
            project_id = project_ids.get(project_name)
            if project_id is None:
                summary.record(
                    "prune",
                    f"{project_name}/{environment}",
                    "skipped",
                    "project does not exist yet",
                )
                continue
            try:
                live = client.list_secrets(
                    project_id=project_id, environment=environment, path="/"
                )
            except InfisicalError as exc:
                summary.fail("prune", f"{project_name}/{environment}", str(exc))
                continue

            for secret in live:
                key = secret.get("secretKey")
                path = secret.get("secretPath") or "/"
                if not key:
                    continue
                if (project_name, environment, path, key) in declared:
                    continue
                target = f"{project_name}/{environment}{path}:{key}"
                if dry_run:
                    summary.secrets_pruned += 1
                    summary.record("prune", target, "would-delete", "not in manifest")
                    continue
                try:
                    client.delete_secret(
                        key,
                        project_id=project_id,
                        environment=environment,
                        secret_path=path,
                    )
                except InfisicalError as exc:
                    summary.fail("prune", target, str(exc))
                    continue
                summary.secrets_pruned += 1
                summary.record("prune", target, "deleted", "not in manifest")

    # -- 7. prune environments ---------------------------------------------
    # Only in declared projects, only undeclared slugs, only when EMPTY. The
    # default trio Infisical used to seed (Development/Staging/Production) is
    # exactly this case: three empty environments nobody declared. Anything
    # holding a secret is kept and named, because step 6 above never listed
    # an undeclared environment and so has no idea what is in it.
    if prune_environments:
        declared_envs: dict[str, set[str]] = {}
        for project_name, environment in env_pairs:
            declared_envs.setdefault(project_name, set()).add(environment)
        for project_name in sorted(declared_envs):
            project_id = project_ids.get(project_name)
            if project_id is None:
                summary.record(
                    "prune-env", project_name, "skipped", "project does not exist yet"
                )
                continue
            try:
                live_project = client.get_project(project_id)
            except InfisicalError as exc:
                summary.fail("prune-env", project_name, f"could not list environments: {exc}")
                continue
            for env in live_project.get("environments") or []:
                slug = env.get("slug")
                env_id = env.get("id")
                if not slug or not env_id or slug in declared_envs[project_name]:
                    continue
                target = f"{project_name}/{slug}"
                try:
                    contents = client.list_secrets(
                        project_id=project_id, environment=slug, path="/"
                    )
                except InfisicalError as exc:
                    summary.fail("prune-env", target, f"could not list secrets: {exc}")
                    continue
                if contents:
                    summary.environments_kept += 1
                    summary.record(
                        "prune-env",
                        target,
                        "kept",
                        f"not declared but holds {len(contents)} secret(s); "
                        "empty it or declare it",
                    )
                    continue
                if dry_run:
                    summary.environments_pruned += 1
                    summary.record("prune-env", target, "would-delete", "not declared, empty")
                    continue
                try:
                    client.delete_environment(project_id, str(env_id))
                except InfisicalError as exc:
                    summary.fail("prune-env", target, str(exc))
                    continue
                summary.environments_pruned += 1
                summary.record("prune-env", target, "deleted", "not declared, empty")

    # Group access is deliberately not reconciled here: it needs different
    # credentials (and, to create a group at all, a database connection), it
    # fails for entirely unrelated reasons, and a `sync` that could not write
    # secrets because a group was missing would be the wrong coupling. See
    # `nixfisical sync-access` and ``access.py``. `groups_seen` above is
    # collected so a plain `sync` still says which groups are outstanding;
    # `hosts` is carried through the manifest and used by nothing yet.

    return summary
