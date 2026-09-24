"""Render an Infisical agent bundle for a host that is not NixOS.

``homeManagerModules.agent`` is the agent for a developer's own machine, and
the README says why there is no NixOS counterpart: a server wants
``nixosModules.inject``, not a polling daemon. This module is for the third
kind of machine -- a shared developer box that is *not* NixOS at all. A Debian
LXC provisioned by Ansible, a CI runner, a workstation image. It has the
upstream ``infisical`` binary and systemd, and nothing that can evaluate a
home-manager module.

So the same thing the module computes is computed here and written to disk:
one agent configuration and one dotenv template per ``(project, environment,
folder)`` the manifest exports, for whatever configuration management the host
already has to copy into place. The manifest is the input for the same reason
it is the input to ``sync``: a folder that exists in Infisical because some
secret was annotated is a folder a developer's ``.env`` should be able to
render, with no second list to keep in step.

Two things this does not do, on purpose:

* **It does not place credentials.** The agent authenticates with a
  universal-auth client id and secret read from two files at run time; this
  writes their *paths* into the configuration and nothing else. Minting the
  identity is ``nixfisical provision-host``; delivering the two files is the
  host's own configuration management, the same as for the home-manager
  module. A bundle is therefore safe to commit or to ship through a plain
  file copy.

* **It does not install a unit.** What runs ``infisical agent --config`` and
  when is the host's business. The bundle carries the list of destination
  paths so the host can create the tree with the modes it wants before the
  agent starts, which is the one piece of preparation the home-manager module
  does that a file bundle cannot.

Project ids are the one input the manifest lacks: Infisical addresses a
project by id in the template engine and the manifest names projects. The CLI
resolves them against the instance, or takes them pinned, and hands them here;
this module never talks to a server.

The template text is byte-identical to ``nixfisicalLib.mkDotenvTemplate``,
kept so in :func:`dotenv_template`. If one changes the other must, and the
test for it says why.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml

__all__ = [
    "AgentConfigError",
    "TemplateSpec",
    "dotenv_template",
    "plan_templates",
    "render_agent_config",
    "write_bundle",
]


class AgentConfigError(ValueError):
    """The bundle cannot be rendered from what was given."""


@dataclass(frozen=True)
class TemplateSpec:
    """One dotenv file to render: a folder of one project in one environment.

    :func:`plan_templates` returns these in a fixed order -- project, then
    folder, then environment -- so a rendered bundle is stable across runs and
    a folder's environments sit together in the YAML. A configuration file
    whose template list reorders itself shows a diff on every deploy and so is
    never read.
    """

    project: str
    environment: str
    folder: str

    @property
    def slug(self) -> str:
        """A filesystem-safe name for the template file.

        ``project__folder__environment``, with the folder's slashes doubled
        into underscores and the root folder spelled ``root``. Flat rather
        than nested so the templates directory can be listed at a glance and
        the YAML's ``source-path`` entries are one directory deep.
        """
        relative = self.folder.strip("/").replace("/", "__") or "root"
        return f"{self.project}__{relative}__{self.environment}"

    def destination(self, dest_root: str) -> str:
        """Where the rendered ``.env`` lands on the target host.

        ``<root>/<project>/<folder>/<environment>.env``. The environment is the
        file name rather than a directory because it is the axis a developer
        switches along: the same folder on mainnet and on testnet4 sit side by
        side in one directory, and an application points at one file.
        """
        relative = self.folder.strip("/")
        parts = [dest_root.rstrip("/"), self.project]
        if relative:
            parts.append(relative)
        parts.append(f"{self.environment}.env")
        return "/".join(parts)


def dotenv_template(
    project_id: str,
    environment: str,
    secret_path: str = "/",
    *,
    recursive: bool = False,
    expand_secret_references: bool = True,
) -> str:
    """The Go template that dumps one folder as a dotenv file.

    Mirrors ``nixfisicalLib.mkDotenvTemplate`` exactly, down to the modifier's
    key order (Nix's ``toJSON`` sorts attribute names) and the ``{{-``
    trimming that keeps the output free of the blank lines some dotenv parsers
    read as end-of-file. ``text/template`` is whitespace-significant, which is
    why this is a string with explicit newlines and not a pretty one.
    """
    modifier = json.dumps(
        {"expandSecretReferences": expand_secret_references, "recursive": recursive},
        separators=(",", ":"),
        sort_keys=True,
    )
    return (
        f'{{{{- with listSecrets "{project_id}" "{environment}" "{secret_path}" `{modifier}` }}}}\n'
        "{{- range . }}\n"
        "{{ .Key }}={{ .Value }}\n"
        "{{- end }}\n"
        "{{- end }}\n"
    )


def plan_templates(
    manifest: Iterable[dict[str, Any]],
    groups: set[str] | None = None,
) -> list[TemplateSpec]:
    """Every distinct ``(project, environment, folder)`` the manifest exports.

    ``groups`` narrows it to folders that at least one entry exports to one of
    those groups -- the way to render a developers' bundle from a manifest
    that also carries operator-only folders. ``None`` means everything.

    Deliberately blind to ``source``: a folder is rendered whether its values
    came from SOPS, from the instance, or as literals, because the agent
    reads the live instance and the origin of a value is not the developer's
    concern.
    """
    specs: set[TemplateSpec] = set()
    for entry in manifest:
        project = entry.get("project")
        environment = entry.get("environment")
        if not project or not environment:
            continue
        if groups is not None:
            declared = {g for g in (entry.get("groups") or []) if isinstance(g, str)}
            if not declared & groups:
                continue
        folder = str(entry.get("folder") or "/")
        specs.add(TemplateSpec(str(project), str(environment), folder))
    return sorted(specs, key=lambda s: (s.project, s.folder, s.environment))


def render_agent_config(
    specs: Iterable[TemplateSpec],
    *,
    address: str,
    project_ids: dict[str, str],
    client_id_file: str,
    client_secret_file: str,
    install_root: str,
    dest_root: str,
    polling_interval: str = "60s",
) -> tuple[dict[str, Any], dict[str, str]]:
    """The agent configuration and its templates, as data.

    Returns ``(config, templates)`` where ``config`` is the YAML document the
    agent takes with ``--config`` and ``templates`` maps each spec's slug to
    its template text. ``install_root`` is where the bundle will live on the
    *target* host; every ``source-path`` is written under it, so the bundle is
    rendered once and copied, not rendered on the host.

    The document's shape follows the home-manager module's ``agentConfig``
    exactly, including upstream's inconsistent spelling of
    ``remove_client_secret_on_read``: that is the struct tag, and a
    hyphenated version unmarshals to nothing.
    """
    specs = list(specs)
    missing = sorted({s.project for s in specs} - set(project_ids))
    if missing:
        raise AgentConfigError(
            "no project id for: "
            + ", ".join(missing)
            + ". Run 'sync' so the project exists, or pin it with --project-id NAME=ID."
        )

    templates: dict[str, str] = {}
    entries: list[dict[str, Any]] = []
    root = install_root.rstrip("/")
    for spec in specs:
        templates[spec.slug] = dotenv_template(
            project_ids[spec.project], spec.environment, spec.folder
        )
        entries.append(
            {
                "source-path": f"{root}/templates/{spec.slug}.tmpl",
                "destination-path": spec.destination(dest_root),
                "config": {"polling-interval": polling_interval},
            }
        )

    config: dict[str, Any] = {
        "infisical": {
            "address": address,
            "exit-after-auth": False,
            "revoke-credentials-on-shutdown": False,
        },
        "auth": {
            "type": "universal-auth",
            "config": {
                "client-id": client_id_file,
                "client-secret": client_secret_file,
                "remove_client_secret_on_read": False,
            },
        },
        "sinks": [],
        "templates": entries,
    }
    return config, templates


def write_bundle(
    out_dir: Path,
    config: dict[str, Any],
    templates: dict[str, str],
) -> list[Path]:
    """Write ``agent.yaml``, ``templates/*.tmpl`` and ``destinations.txt``.

    ``destinations.txt`` is one destination path per line, in template order:
    the list a host needs to create the ``.env`` tree with the modes it wants
    before the agent's first render, since ``os.Create`` leaves a fresh file
    at 0644 and a secret should not spend even its first second there.

    Returns the paths written. Nothing in the bundle is a secret, so the files
    are written at the default mode and may be committed.
    """
    out_dir = Path(out_dir)
    templates_dir = out_dir / "templates"
    templates_dir.mkdir(parents=True, exist_ok=True)

    written: list[Path] = []
    config_path = out_dir / "agent.yaml"
    config_path.write_text(
        yaml.safe_dump(config, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
    )
    written.append(config_path)

    for slug, text in templates.items():
        path = templates_dir / f"{slug}.tmpl"
        path.write_text(text, encoding="utf-8")
        written.append(path)

    destinations = out_dir / "destinations.txt"
    destinations.write_text(
        "".join(f"{t['destination-path']}\n" for t in config.get("templates", [])),
        encoding="utf-8",
    )
    written.append(destinations)
    return written
