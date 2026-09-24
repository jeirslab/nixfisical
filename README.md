# nixfisical

Declarative [Infisical](https://infisical.com) for NixOS fleets.

nixpkgs ships the Infisical **client** (`pkgs.infisical`, the Go CLI) and
nothing else — no `services.infisical`, no server package. So everyone
self-hosting Infisical writes the same three things by hand: a container unit,
a one-shot bootstrap script, and a sync job that pushes secrets up from
wherever they actually live. This repo is those three things, written once.

It exists because a fleet's real secrets already live in SOPS, encrypted to
host keys, deployed by sops-nix. Infisical is the *developer-facing* view of a
subset of them. Keeping the two in agreement by hand does not scale and fails
in the direction that matters: a secret rotated in SOPS and redeployed leaves
a stale value in Infisical, and developers debug against a credential that
stopped working an hour ago.

**Status: experimental (v0.1.0).** The manifest and CLI are ported from a
working Ansible role driving a production fleet. The native (non-container)
server backend builds and evaluates but has not yet been run against a live
Postgres — see [docs/native.md](docs/native.md).

## The idea

SOPS stays the source of truth — with one deliberate exception per secret
(["Secrets Infisical owns"](#secrets-infisical-owns)) and one deliberate
exception per host (["Direct injection"](#direct-injection-experimental)). Each
secret says, at its declaration site,
whether developers should see it and where it belongs:

```nix
{
  imports = [ nixfisical.nixosModules.export ];

  sops.secrets."services/bitcoin/rpc_password" = {
    restartUnits = [ "bitcoind.service" ];

    infisical = nixfisical.lib.mkInfisical {
      project = "bitcoin-nodes";     # the hard access boundary
      folder  = "/mainnet";
      groups  = [ "developers" ];
      name    = "RPC_PASSWORD";      # defaults to the last key segment
    };
  };
}
```

A secret with no `infisical` block is infra-only: it stays in SOPS and never
reaches Infisical. Exporting is opt-in per secret, because a fleet's SOPS file
is full of things developers must not see.

SOPS is the default source of truth, not the only one: a secret the instance
mints rather than receives says `source = "infisical"` and travels the other
way. See [Secrets Infisical owns](#secrets-infisical-owns).

Importing `nixosModules.export` costs one deploy. sops-nix serialises the
whole secret submodule into its on-host `manifest.json`, unknown fields and
all, so `"infisical": null` appears against every secret as soon as the module
is imported — which moves the manifest's store path and so every sops-using
host's `toplevel`. The activation itself is a no-op (`sops-install-secrets`
ignores the field and its `-check-mode=sopsfile` validation accepts it); it is
a rebuild, not a behaviour change. Two practical consequences: import the
module in the same change as your first annotations rather than ahead of them,
and remember that `project` / `folder` / `groups` end up in a world-readable
store path on each host — no values, but the folder names are visible.

`nixfisical.lib.manifestOf` then walks every host and collects those
annotations into one manifest — structure only, no values, nothing decrypted
in the Nix store:

```json
[
  {
    "sopsKey":  "services/bitcoin/rpc_password",
    "sopsFile": "/fleet/nix/secrets/btc-nodes.yaml",
    "project":  "bitcoin-nodes",
    "environment": "prod",
    "folder":   "/mainnet",
    "name":     "RPC_PASSWORD",
    "groups":   ["developers"],
    "hosts":    ["btc-mainnet"]
  }
]
```

`sopsKey` is the path *inside the encrypted file*, which is
`sops.secrets.<n>.key` and only defaults to the attribute name. If you name an
attribute `cli-proxy/api_key` for legibility on the host and set
`key = "api_key"` because the file is flat, the manifest exports `api_key`.
`name` defaults to the last segment of that same resolved key.

`nixfisical sync` reads that, decrypts each value **on your machine at run
time**, and converges the remote instance onto it: missing projects,
environments and folders get created, values get upserted, and secrets the
manifest no longer declares get pruned.

Because the declaration lives next to the secret, rotation is automatic. Change
the value in SOPS, redeploy, run the sync — Infisical follows. There is no
second list to remember to update.

### Secrets no host holds

Riding on `sops.secrets` means the exported set is exactly the set some machine
consumes, which is the right default. It breaks down for a credential whose
only consumer is a person or an agent's client — a mailbox password the mail
host verifies as a `$6$` hash and must never hold in plaintext, an API token
you hand out but never deploy. Declaring one on a host to make the export work
puts a lie in the fleet's manifest, and sops-nix would then materialise the
credential on a machine with no use for it.

Name those directly instead, and pass them as `extraSecrets`:

```nix
packages.infisical-manifest = nixfisical.mkManifestApp {
  inherit pkgs;
  nixosConfigurations = self.nixosConfigurations;
  extraSecrets = [
    (nixfisical.lib.mkExportOnly {
      sopsFile = ./secrets/mail-clients.yaml;
      sopsKey  = "mail.engine_password";
      project  = "platform";
      folder   = "/mail";
      name     = "ENGINE_MAILBOX_PASSWORD";
    })
  ];
};
```

The result is an ordinary manifest entry with `"hosts": []`, validated, deduped
and **pruned** like any other: delete the `mkExportOnly` call and the next sync
deletes the secret from Infisical. The SOPS file still has to be decryptable by
whoever runs the sync — an entry says where a secret goes, never who may read
it. `mkSyncApp` takes the same argument.

Use it for secrets no host can honestly declare, not as a shortcut around
annotating one that can: an export-only entry has no `restartUnits`, no
rotation path through a deploy, and nothing tying it to the thing that uses it.

### Secrets Infisical owns

Some values are not yours to author. An OIDC client secret is minted by the
identity provider, a webhook signing key is shown once by the SaaS that issues
it, a developer rotates a shared API token in the UI at 2am. SOPS can hold
those — it has to, because the host needs them — but it did not produce them,
and a `sync` that pushes the local copy up will quietly overwrite the real one.

Say so at the declaration site:

```nix
sops.secrets."services/grafana/oidc_secret" = {
  restartUnits = [ "grafana.service" ];

  infisical = nixfisical.lib.mkInfisical {
    project = "platform";
    folder  = "/grafana";
    name    = "OIDC_CLIENT_SECRET";
    source  = "infisical";          # defaults to "sops"
  };
};
```

`source` names which side owns the **value**. Everything else about the entry
is unchanged: it is still in the manifest, still gets its project, environment
and folder created, still gets its group access applied, and — importantly —
is still *declared*, so `sync --prune` leaves it alone rather than deleting a
secret it has been told not to write.

What changes is who writes what:

```
sync    writes the values of  source = "sops"       entries. Never the others.
import  writes the values of  source = "infisical"  entries, into their SOPS files.
```

The two write sets are disjoint by construction, which is the whole safety
argument. There is no bidirectional sync here and no conflict resolution,
because no secret is ever written by both commands. A pull cannot clobber a
rotation you just pushed, and a `sync` run from a stale checkout cannot undo a
value it never had.

```sh
# Pull every instance-owned value down into the SOPS files that hold it.
nix run .#infisical-manifest | nixfisical --url https://infisical.example.com import --dry-run
nix run .#infisical-manifest | nixfisical --url https://infisical.example.com import
```

`import` decrypts and rewrites each destination file **once**, not once per
secret — a token-backed age key asks for one touch per file, not one per
value. A value that already matches is not written at all: an import with no
news leaves every file byte-identical, so a changed file in `git status` means
something actually changed. Review the diff and commit it; nothing is pushed
for you.

**The ordering constraint.** sops-nix reads the file, not the instance, so a
host cannot deploy a secret that is not in its SOPS file yet. A newly declared
`source = "infisical"` entry therefore goes **declare → import → deploy**, in
that order. Import before the entry exists in Infisical and the run fails
naming the coordinate; deploy before the import and activation fails with a
missing key. Both fail closed, which is correct, but the order is not optional.

`import` and `sync` stay separate commands rather than one converge step
because they can fail for unrelated reasons — the instance being unreachable
versus a SOPS file you cannot decrypt — and folding them together would mean
one exit code answering two questions.

### Secrets Infisical pushes onward

A **secret sync** is the other direction: Infisical pushing one folder of one
environment into somewhere else -- GitHub Actions secrets, Parameter Store,
another Infisical -- on its own schedule, with no host and no operator in the
loop. Declare them next to the secrets they push, in the API's own field
names, and hand the list to the sync app:

```nix
infisical-sync = nixfisical.mkSyncApp {
  inherit pkgs;
  inherit (self) nixosConfigurations;
  url = "https://infisical.example.com";
  # The App key the org engine mints tokens with: no host holds it, so it
  # is export-only, and it lives in its own project.
  extraSecrets = [
    (nixfisical.lib.mkExportOnly {
      sopsFile = ./secrets/org-engine.yaml; sopsKey = "github_app/private_key";
      project = "org-engine"; name = "ORG_APP_PRIVATE_KEY";
    })
  ];
  # ...and every repository that must receive it.
  syncs = map (repo: nixfisical.lib.mkGithubSync {
    owner = "example"; inherit repo;
    project = "org-engine"; connection = "example-github";
  }) [ ".github" "platform" "api" ];
};
```

`nix run .#infisical-sync` now runs three commands in order: `sync` (projects,
folders, secret values), **`syncs`** (the outbound syncs, which need those
projects to exist), then `sync-access`. `--dry-run` covers all three.

What `syncs` does and does not do:

- `project` and `connection` are **names**; the reconciler resolves the ids.
- A connection is **never created**. Authorising one is a browser round-trip
  with the provider (for GitHub, an App the instance admin registers and
  installs), so it is done once in the UI under *App Connections*, with the
  name the declaration uses. A declared connection that does not exist is an
  error for that sync; the others still converge.
- Drift is patched field by field; a changed `destination` is refused, because
  that is a different sync (remove it, let prune delete it, re-declare).
- **Prune is per project**: an undeclared sync in a declared project is
  deleted, and nothing outside declared projects is touched. Deleting a sync
  never removes what it already wrote downstream.
- `--run` triggers every declared sync after converging -- the first push, or
  a forced re-push. Creation already starts one when auto-sync is on.

`mkGithubSync` is the one-repository case (`scope = "repository"`); GitHub
accepts only `overwrite-destination` as the initial behaviour because Actions
secrets cannot be read back, so that is not a parameter. `mkSync` is the
generic form for the other 48 destinations: pass `destination`,
`syncOptions` and `destinationConfig` exactly as `docs/openapi.json` spells
them, and `app` when the connection kind differs from the destination slug
(`aws-parameter-store` connects through `aws`).

## Quick start

```sh
# 1. Deploy the server (see "Running the server" below), then:

# 2. Bootstrap: create the superadmin, the org, and a `fleet-sync` machine
#    identity, and record all of it in a SOPS-encrypted admin file.
#    (Instance already initialised? Use `adopt` instead — see "Adopting an
#    instance you did not bootstrap". `nixfisical status` will tell you which.)
nix run github:jeirslab/nixfisical -- \
  --url https://infisical.example.com \
  --admin-file nix/secrets/infisical-admin.yaml \
  bootstrap --organization "Example" --git-commit

# 3. Render your fleet's manifest and check it before touching anything.
nix run .#infisical-manifest -- table
nix run .#infisical-manifest | nixfisical --url https://infisical.example.com sync --dry-run

# 4. Converge.
nix run .#infisical-manifest | nixfisical --url https://infisical.example.com sync
```

`--dry-run` reads everything and writes nothing, and it decrypts each value
before discarding it — so a renamed or rotated-away SOPS key fails the dry run
rather than the real sync. It reports exactly which secrets would be created,
updated, and **deleted**. Run it first.

## Flake outputs

| Output | What it is |
| --- | --- |
| `lib.mkInfisical` | Annotate a `sops.secrets` entry for export. |
| `lib.mkExportOnly` | Export a secret no host declares. |
| `lib.manifestOf` | `nixosConfigurations` → manifest list. |
| `lib.manifestFrom` | `{ nixosConfigurations, extraSecrets }` → manifest list. |
| `lib.assertManifest` | Fail evaluation on a malformed manifest. |
| `lib.mkDotenvTemplate` | A Go template dumping one Infisical folder as dotenv. |
| `mkManifestApp` | Wrap a manifest as a `nix run .#infisical-manifest` app. |
| `nixosModules.export` | Adds `sops.secrets.<key>.infisical`. |
| `nixosModules.server` | Runs a self-hosted instance. |
| `nixosModules.default` | Both of the above. |
| `nixosModules.inject` | Fetches this host's secrets from Infisical at boot. Experimental; **not** in `default`. |
| `homeManagerModules.agent` | Upstream's Infisical agent as a `systemd.user` service, rendering templates into a developer's tree. |
| `packages.nixfisical` | The `nixfisical` CLI. |
| `packages.nixfisical-agent` | The host halves — `nixfisical-agent` and `nixfisical-keyring-install` — without the CLI or its closure. |
| `packages.infisical-backend` | The Infisical API, built from source. No web UI. |
| `packages.infisical-frontend` | The Infisical web UI, as static files. |
| `packages.infisical-standalone` | Both, with the API serving the UI. |
| `packages.docs` | Every option and every CLI command, generated. See "The agent surface". |
| `apps.mcp` | An MCP server over a live instance. Read-only by default. |
| `overlays.default` | Puts all of the packages in your package set. |

Wiring the manifest app into a consumer flake:

```nix
packages.${system}.infisical-manifest = nixfisical.mkManifestApp {
  inherit pkgs;
  nixosConfigurations = self.nixosConfigurations;
};
```

## Running the server

```nix
{
  imports = [ nixfisical.nixosModules.server ];

  virtualisation.oci-containers.backend = "docker";

  services.infisical = {
    enable   = true;
    siteUrl  = "https://infisical.example.com";
    imageTag = "v0.165.8";               # pin it; migrations run on start

    database = {
      host = "10.0.0.11";
      user = "infisical";
      name = "infisical";
    };
    redis.host = "10.0.0.10";

    smtp = {
      enable      = true;
      host        = "smtp.example.com";
      username    = "no-reply@example.com";
      fromAddress = "no-reply@example.com";
    };

    # Only the secrets live here now: see the table below.
    environmentFiles = [ config.sops.templates."infisical-env".path ];
  };

  sops.templates."infisical-env".content = ''
    ENCRYPTION_KEY=${config.sops.placeholder."services/infisical/encryption_key"}
    AUTH_SECRET=${config.sops.placeholder."services/infisical/auth_secret"}
    DB_PASSWORD=${config.sops.placeholder."dbs/infisical/password"}
    SMTP_PASSWORD=${config.sops.placeholder."services/infisical/smtp_password"}
  '';
}
```

Postgres and Valkey/Redis are yours to provide — the module does not manage
them, on purpose: in a fleet they usually live on separate hosts with their own
backup and blast-radius story. What the module does give you is the full
configuration surface for reaching them, so the only thing left in your sops
template is the credentials themselves.

### Which settings are options, and which are secrets

Infisical accepts the database connection either as one `DB_CONNECTION_URI` or
as discrete `DB_HOST`/`DB_PORT`/`DB_USER`/`DB_NAME`/`DB_PASSWORD` variables
(the URI wins when both are set, so the module refuses to evaluate if you
configure both). Discrete is the default here for one reason: a connection URI
embeds the password, so it can only ever come from an env file, while
host/port/user/name are not secret and belong in configuration you can read and
review.

| Secret — `environmentFiles` only | Option — safe in the store |
| -------------------------------- | -------------------------- |
| `ENCRYPTION_KEY`, `AUTH_SECRET`  | `siteUrl`, `host`, `port`  |
| `DB_PASSWORD`                    | `database.{host,port,user,name}` |
| `REDIS_PASSWORD`                 | `redis.{host,port,username}`, `database.rootCert` |
| `SMTP_PASSWORD`                  | `smtp.{host,port,username,fromAddress,…}` |
| `DB_READ_REPLICAS` (JSON of URIs)| `database.{poolMin,poolMax}` |

**Every option above defaults to null, and the module emits a variable only
when you set the matching option.** That is deliberate. For the `oci` backend
the options become `-e KEY=value` while `environmentFiles` becomes
`--env-file`, and Docker and Podman resolve `-e` *ahead of* `--env-file`. If
the module emitted defaults, an env file supplying the same key would be read
and silently ignored. Leaving an option null keeps the variable out of the
store entirely, so a fleet that treats (say) `SMTP_HOST` as sensitive can still
supply it from sops. The same rule applies to `extraEnvironment`.

Settings the module does not model as options — Redis Sentinel and Cluster
topologies, queue worker profiles, SSO — go through `extraEnvironment`.

### Do not use the `latest-postgres` tag

Infisical's older self-hosting docs recommend `infisical/infisical:latest-postgres`,
and it is a common default in hand-rolled deployments. It is a trap now. The
`-postgres` suffix dates from when Infisical also shipped a MongoDB variant;
upstream stopped publishing it. The tag still resolves, so nothing fails — but
it has not been rebuilt since **2025-08-08**, while `latest` rebuilt yesterday.
It is a silently frozen year-old image, not a moving pointer, and no
`-postgres` tag appears in the most recent 100 tags (checked 2026-09-09). If
you have a deployment on `latest-postgres`, it is a year behind and does not
look it. Pin `v0.165.8` or similar instead.

The module refuses to evaluate with an empty `environmentFiles` rather than
booting an instance with a default encryption key. Nothing secret is ever
written to the Nix store; `extraEnvironment` is for non-secret values only.

### The `native` backend

Every option above is backend-agnostic — they describe the server's
configuration, not how it is packaged — so swapping the container for a plain
systemd unit is one line plus the overlay:

```nix
{
  nixpkgs.overlays = [ nixfisical.overlays.default ];

  services.infisical = {
    backend = "native";                  # was "oci"
    # imageTag and virtualisation.oci-containers.backend become unused
    # ... everything else unchanged ...
  };
}
```

That builds Infisical from source at a rev pinned in this flake, and splits the
image's conflated entrypoint in two:

| Unit                        | Does                                |
| --------------------------- | ----------------------------------- |
| `infisical.service`         | runs the API. Never migrates.       |
| `infisical-migrate.service` | runs migrations. Nothing else does. |

`database.autoMigrate` defaults to **false**, the opposite of the usual NixOS
default. Infisical's migrations are not uniformly reversible — one of them
drops six tables and defines `down()` as a no-op — so an upgrade should be a
deliberate act, not something a reboot does:

```sh
infisical-migrate status          # what is pending
systemctl start infisical-migrate # after a backup
systemctl restart infisical
```

**The web UI is opt-in.** `package` defaults to `pkgs.infisical-backend`, which
is the API and nothing else — a browser pointed at it gets `{"statusCode":404}`,
not a login page. For the UI:

```nix
services.infisical.package = pkgs.infisical-standalone;
```

That is the same server with the frontend's static build placed where it looks
for it, and `STANDALONE_MODE` set by the package's own wrapper. There is no
module option, because the server crashes on start rather than 404s if the flag
is set on a build with no UI in it — choosing the package cannot be wrong that
way. `docs/native.md` has the details.

Bump the pinned release with `nix run .#bump-infisical -- 0.166.0`. It moves
the release and all three hashes together; the backend and the frontend must
come from the same tag.

[docs/native.md](docs/native.md) has the packaging details, including why
upstream's `migration:latest` is three steps rather than the one
`knex migrate:latest` you would expect.

**Option namespace.** This module claims `services.infisical`. If you also
import [`connerohnesorge/infisical-flake`](https://github.com/connerohnesorge/infisical-flake),
which claims the same path, the two will conflict — pick one.

## The CLI

```
nixfisical bootstrap     initialise a fresh instance, record creds in SOPS
nixfisical adopt         same, for an instance that is already initialised
nixfisical add-org       same end state, for an additional organization
nixfisical sync          converge the instance onto a manifest
nixfisical import        pull instance-owned values down into their SOPS files
nixfisical sync-access   grant manifest groups access to their projects
nixfisical provision-host mint a host's own scoped identity into its SOPS file
nixfisical validate      check a manifest offline (exit 2 on problems)
nixfisical status        is it reachable, and does the sync identity still work
nixfisical secrets       read, write and mint the SOPS values the rest reads
nixfisical keyring       store the estate's age key, and audit who can read it
```

Bootstrap is the destructive one, so it is guarded properly. If the admin file
already exists, it **logs in with the recorded sync identity** and exits
successfully if that works — so it is safe to run unconditionally as a
first-deploy step. If the file exists but the login fails, it stops and says
so instead of re-bootstrapping over a live instance; recovering is a
deliberate act, not a default. Rendering the admin file and encrypting it is
one step: if `sops --encrypt` fails, the plaintext is deleted before the error
propagates.

`--git-commit` commits the encrypted admin file (never pushes), so a
first-deploy run leaves the credentials tracked rather than sitting untracked
in a working tree waiting to be lost.

### Adopting an instance you did not bootstrap

`POST /api/v1/admin/bootstrap` succeeds exactly **once** in an instance's life.
An instance someone clicked through the setup wizard on, or one whose admin
file was lost with an old checkout, is therefore permanently out of
`bootstrap`'s reach — and short of dropping its database there was no way to
bring it under declarative management.

`adopt` is that way. It ends at the same admin file, reached from the other
side: instead of creating the superadmin and the organization it authenticates
as the superadmin that exists and finds the organization that exists, then runs
exactly the same tail — mint `fleet-sync`, write the file. Nothing downstream
can tell which command produced a given admin file.

```sh
nixfisical --url https://infisical.example.com adopt \
  --admin-email admin@example.com \
  --admin-password-from secrets/infisical.yaml:admin_password
```

`--organization` is optional when the account belongs to exactly one; with
more than one it is required, and the error lists them. Matching is by id,
then slug, then name.

Two differences from `bootstrap` that are not cosmetic:

- **The superadmin password is an input, not an output.** Bootstrap generates
  one that nobody ever types and the admin file is its only copy. Adopt has to
  be *given* the password of an account a human already logs in with, and
  records it alongside the machine credentials. Rotate it afterwards if that
  matters. There is no generate fallback — inventing a password for an account
  that exists would produce a confident "Invalid credentials".
- **It refuses to reuse an identity name.** If the organization already has a
  machine identity called `fleet-sync`, adopt stops. Infisical shows a client
  secret once, at creation, so an existing identity cannot be adopted into an
  admin file at all — there is nothing to read back. Delete it, or pass
  `--identity-name`.

MFA on the superadmin account stops adopt, by design. Upstream enforces it at
organization selection rather than at login, so the refusal happens after the
password has been accepted; completing a TOTP challenge belongs in an
interactive tool, not in something that may be running from a deploy script.

`status` reads "has this been initialised?" off the instance
(`GET /api/v1/admin/config`) rather than inferring it from whether an admin
file happens to exist locally. Those are independent facts, and the case where
they disagree — initialised instance, no admin file — is exactly the one
`adopt` exists for, so it is the one worth naming rather than mislabelling as
"not bootstrapped yet".

### A second organization on one instance

`bootstrap` creates the first organization and is then spent forever; `adopt`
only finds organizations that already exist. Neither can give you a second one,
and a second one is what you want when two estates share a server: an access
token is scoped to exactly one organization, so the organization — not the
project — is the blast radius.

That partition is worth stating as measured rather than assumed. Against
v0.165.8, with two machine identities and one organization id: the identity
that owns it lists its two projects, the identity that does not lists none.
How the refusal is *phrased* varies by route — `GET /api/v1/identities`
answers 403 and names both organizations, `GET /api/v2/organizations/{id}/workspaces`
answers 200 and an empty list. Both refuse; only one says so. So an
unexpectedly empty project list means the wrong admin file, not an empty
organization.

`add-org` runs after whichever of `bootstrap`/`adopt` applied, once per extra
organization. It takes **two** admin files, which is the only genuinely
confusing thing about it: the global `--admin-file` is the instance's and is
*read* (creating an organization needs a human superadmin, and for a
bootstrapped instance that generated password's only copy is in there);
`--org-admin-file` is the new one being *written*.

```sh
nixfisical --url https://infisical.example.com \
  --admin-file secrets/infisical-admin.yaml \
  add-org --organization 'XG Capital Strategies' \
          --org-admin-file secrets/infisical-admin-xgcs.yaml \
          --git-commit
```

From then on, that file is the one every other command takes:

```sh
nixfisical --admin-file secrets/infisical-admin-xgcs.yaml sync --manifest ...
```

Unlike group creation, organization creation is **not** plan-gated. The
free-tier instance answers 200 to `POST /api/v2/organizations` while answering
400 "Failed to create group due to plan restriction" to `POST /api/v1/groups`,
so `add-org` needs none of the direct-to-Postgres machinery that
`--create-missing-groups` does.

Two things worth knowing about the file it writes:

- **It carries no superadmin block by default.** That block is write-only in
  this tool — `bootstrap` and `adopt` write it, and nothing on the `sync`,
  `sync-access` or `status` path ever reads it back. Omitting it therefore
  costs nothing and avoids copying an *instance*-scoped superadmin password
  into a second estate's repo, where whoever can decrypt it would own every
  organization on the server. Pass `--record-admin-credentials` when the new
  organization is another slice of the same estate and you want the
  bootstrap/adopt file shape back.
- **Re-running is safe, and deliberately so.** Infisical does not enforce
  unique organization names, so a naive implementation would mint a twin on
  every run. The organization is looked up by id, then slug, then name — the
  same rule `adopt` uses to select one, shared code precisely so the find rule
  cannot drift from the create rule — and the org admin file gates the command
  exactly as it gates the other two: if its identity can log in, there is
  nothing to do.

The slug is derived from the name by the server, with a random suffix for
uniqueness, and cannot be chosen (`xg-capital-strategies-6-ec-e`). Match on the
name or the id.

### Group access

`sync-access` reads the same manifest as `sync` and grants each `groups` entry
access to the projects it appears in. It is a separate command on purpose: it
needs different credentials, it fails for entirely unrelated reasons, and a
`sync` that refused to write secrets because a group was missing would be the
wrong coupling.

Access is granted at the **project** level. A group named on any entry of a
project gets the whole project, so `project` is the access boundary the
manifest actually expresses — `environment` and `folder` do not narrow it.
Access is never revoked; remove it in the UI.

Two mechanisms, and the split matters:

- **Adding an existing group to a project** is a supported, ungated API call.
  This runs by default and needs nothing but the sync identity.
- **Creating a group** is gated behind an enterprise plan. Upstream's
  `getDefaultOnPremFeatures()` sets `groups: false`, and the create endpoint
  answers `400 plan restriction`.

So `--create-missing-groups` writes to Infisical's Postgres directly. It is off
by default, prints a warning when set, and is the only operation in this tool
that touches the database. Point it at the database with `--db-host` and give
it a password via `--db-password-from FILE:KEY` (SOPS) or `$PGPASSWORD`.

The load-bearing asymmetry that makes this safe rather than merely expedient:
upstream gates group *mutation*, but not permission *evaluation*. A group
created this way is honoured by the permission service exactly like any other
— `permission-service.ts` contains no license check. This is not forging an
entitlement, it is writing the rows the UI would have written.

Because it is raw SQL against a schema with no compatibility promise, it
refuses to run on a schema it does not recognise rather than corrupting one.
A preflight checks every column it writes and aborts if any pre-`v0.165.8`
membership table is still present — the schema was consolidated into
`memberships`/`membership_roles` by migration
`20260107083948_remove-old-memberships`, whose `down()` is a no-op. The schema
it is verified against is recorded in `access.py` as
`SCHEMA_VERIFIED_AGAINST`.

Run it with `--dry-run` first; it reports every group it would create and
every grant it would make, and writes nothing.

### Operator membership

A project created by `sync` is visible to **nobody**. `sync` authenticates as a
machine identity, so that identity becomes the project's admin and no human is
a member at all — not even an organization admin. The symptom is logging into a
freshly synced instance, seeing an empty project list, and concluding the sync
never ran.

`sync-access` therefore also puts named humans on every project the manifest
touches. With no `--operator` it reads the email out of the admin file, which
is right for an instance-wide admin file and impossible for a per-org one
(`add-org` omits the admin block by design) — those must name someone.

```sh
nixfisical sync-access --operator admin@example.org           # --operator-role, default admin
nixfisical sync-access --operator dev@example.org:viewer      # this person only
nixfisical sync-access --no-operator                          # nobody; see below
```

**On an unlicensed instance this is the only ungated way to give a human any
access at all.** Adding an existing group to a project is ungated, but
*creating* the group is not, so an estate without a licence has no groups to
add. That makes operator membership load-bearing rather than a convenience, and
is why each entry carries its own role: the person who administers the instance
needs `admin`, and a developer handed read access must not get it. One shared
`--operator-role` could not express that, and two runs cannot work around it —
the second finds the first's membership already present and leaves it alone.

The `:` separator is not arbitrary. `=` is valid in an RFC 5322 local part and
would corrupt real addresses; `:` cannot appear in one.

Two limits worth knowing before you rely on it:

- **The person must already be a member of the organization.** Upstream calls
  the route "invite members to project", but it sends no invitation for an
  existing member and does nothing for anyone else. Invite them to the org
  first, in the UI.
- **An existing membership is reported, never changed.** If someone holds
  `admin` and the manifest asks for `viewer`, the run says so and moves on.
  Access is never revoked here, and silently lowering a role on the strength of
  a generated file is the same mistake in the other direction. Change it in the
  UI.

`--no-operator` leaves projects whose only member is the sync identity. That is
a real choice for a genuinely unattended estate and a bad surprise anywhere
else.

### Minting and editing secrets

`secrets` is the local half of the tool. It talks to no instance — it operates
on exactly the SOPS files the manifest points at, which is why it lives here
rather than in a second binary. An estate that keeps its source of truth in
SOPS and projects it into Infisical should not need two tools to do it.

```
nixfisical secrets list                    every leaf key path in a store
nixfisical secrets get KEY                 one value, to stdout
nixfisical secrets set KEY [VALUE]         prompted and confirmed if VALUE is omitted
nixfisical secrets rm  KEY                 delete a key, pruning emptied parents
nixfisical secrets edit                    hand off to `sops` on the whole file
nixfisical secrets gen  KIND               mint fresh material
```

The store is named once with `-f/--file` or `$NIXFISICAL_SECRETS_FILE`, on the
group or on any subcommand.

`set` with no `VALUE` and no `--stdin` prompts hidden and confirms, because a
secret passed as an argument is a secret in the shell history and in every
`/proc/*/cmdline` on the box. `--stdin` reads the whole of stdin verbatim, so
multi-line material — a PEM, a private key — round-trips byte for byte.

**`gen` converges, it does not overwrite.** The reason it takes `--into` more
than once is that shared credentials are the common case: Authentik's Postgres
password belongs in the Authentik host's file *and* in the database host's,
an OAuth2 client secret in the provider's file *and* the consumer's. Minting
those by hand means generating once and pasting twice, and the failure mode is
not an error — it is two files that agree today and diverge at the next
rotation, surfacing months later as an authentication failure somewhere
unrelated.

```sh
nixfisical secrets gen alnum --length 48 \
    --into secrets/authentik.yaml:db_password \
    --into secrets/infra-db.yaml:authentik
```

So, given N destinations: if none hold a value it generates one and writes it
to all N; if some hold the same value it propagates that value to the rest and
generates nothing; if all agree it does nothing and exits 0; and if they
*disagree* it refuses, names them, and demands `--rotate` — because deciding
which copy is the stale one is not a call this tool should make silently.
Re-running is a no-op. Adding a fourth consumer later and re-running copies
the existing value into it rather than rotating the other three.

Kinds are named rather than spelled out in `openssl` flags, so the next person
reads `kind: alnum, length: 48` and knows what is in the store without
decrypting it: `alnum`, `hex`, `urlsafe`, `base64`, `password`, `uuid`.
`--length` always counts **output characters**, for every kind — unlike
`openssl rand`, which counts input bytes, and where `-base64 32` yields 44
characters rather than 32. Lengths below 12 are refused.

A service needs six or seven secrets at once, so `--plan` takes the whole set
at once. It is reviewable in a PR and, because generation converges, safe to
re-run at any time:

```yaml
# secrets/authentik.plan.yaml
file: secrets/authentik.yaml     # default store for the bare keys below
secrets:
  - kind: urlsafe
    length: 60
    note: AUTHENTIK_SECRET_KEY
    into: [secret_key]
  - kind: alnum
    length: 48
    note: shared with the database host, must stay byte-identical
    into:
      - db_password
      - secrets/infra-db.yaml:authentik
```

Paths in a plan resolve relative to the plan file's own directory, so a plan
travels with the repo it describes. `--dry-run` reports every write it would
make and performs none. `--print` writes the generated value to stdout for the
one case that needs it — pasting a bootstrap password into a UI once. It is
not for scripts; those should use `secrets get`, which reads the store rather
than racing it.

## Direct injection (experimental)

Everything above keeps SOPS in the path: Infisical is a view, sops-nix does the
delivery, and a rotated value reaches a host on its next deploy. `nixosModules.inject`
is the other arrangement — the host authenticates to the instance itself and
writes the values straight into a tmpfs, no SOPS file involved.

It is a **different trust model, not a better one**, and the three differences
are the whole reason it is opt-in per host:

- **The host holds a credential that can read.** sops-nix gives it a key that
  only decrypts what it was already handed; this gives it an identity that can
  *ask* for anything that identity may read. A compromised host is now a read of
  its whole blast radius, which is why `provision-host` scopes that identity as
  narrowly as the API allows.
- **Boot depends on the network.** An unreachable instance becomes a failure to
  start. That fails closed, which is the right direction, but it puts the
  secrets server in the boot path of everything downstream of it.
- **Rotation stops needing a deploy.** This is the point. A value changed in the
  UI reaches the host on the next agent run, and only the units whose input
  actually changed are restarted.

It does not remove SOPS and cannot: the host needs credentials to authenticate
with, and those arrive by sops-nix like everything else. What changes is the
count — **one SOPS-delivered credential per host** instead of one per secret.

### Give the host an identity

```sh
nixfisical --url https://infisical.example.com provision-host alpha \
  --project platform --project databases \
  --into secrets/alpha.yaml
```

This creates a machine identity `host-alpha` with the organization role
`no-access`, adds it to each named project as `viewer`, mints universal-auth
credentials, and writes them into `secrets/alpha.yaml` under
`infisical/client_id` and `infisical/client_secret`. The org role matters:
`bootstrap` mints `fleet-sync` as an org `admin`, which reaches every project in
the organization, and an identity shaped like that on a host is a host that can
read the whole fleet.

Re-running is safe and mints nothing — an identity that already has credentials
keeps them, because a re-mint writes a new client secret into SOPS while the
running host still holds the old one, and nothing fails until the next deploy.
`--rotate` is how you ask for a new pair on purpose. If the destination file
will not decrypt, the command stops rather than guessing: a file it cannot read
is indistinguishable from one with no credentials in it.

### Declare what the host fetches

```nix
{
  imports = [ nixfisical.nixosModules.inject ];   # not in nixosModules.default

  services.nixfisical.inject = {
    enable = true;
    url = "https://infisical.example.com";
    organizationId = "…";
    identity.clientIdFile     = config.sops.secrets."infisical/client_id".path;
    identity.clientSecretFile = config.sops.secrets."infisical/client_secret".path;
    refreshInterval = "hourly";

    secrets."grafana-oidc" = {
      project = "platform";
      folder  = "/grafana";
      name    = "OIDC_CLIENT_SECRET";
      owner   = "grafana";
      group   = "grafana";
      restartUnits = [ "grafana.service" ];
    };
  };
}
```

That places the value at `/run/nixfisical/grafana-oidc`, owned `grafana:grafana`
mode `0400`, and restarts `grafana.service` only when the value **actually
changes** — not when the store path moves, and never for a unit that was
deliberately stopped. `refreshInterval` is what makes "rotate without a deploy"
reach the host unattended; without it the agent runs at boot and on demand only.

Two units, which is worth knowing before you go looking for one:
`nixfisical-agent.service` is the boot unit — `RemainAfterExit`, so ordering
against it means something — and `nixfisical-agent-refresh.service` is what the
timer starts, and what to `systemctl start` by hand to pull a rotation down now.
They cannot be one unit: a start job on an already-active oneshot returns
`-EALREADY` and runs nothing, so a timer aimed at the boot unit would fire on
schedule, log success, and never fetch a thing.

Consumers should order against the boot unit with `Wants=` + `After=`, not
`Requires=`: a restart propagates to everything that requires the unit, which
would undo the point of restarting only on a real change. Order against it, and
make the consumer fail closed on a missing file on its own.

The spec the module generates is world-readable in the store and carries
coordinates, destinations and ownership but **no values** — the same bargain
sops-nix's manifest makes. Folder and secret names are visible to any local
user.

This module and `nixosModules.export` are not alternatives. A secret SOPS owns
and Infisical mirrors is what the export path is for; one Infisical owns and
this host reads is what this is for; both can be true on one host.

### The cache trade

`cache.enable` keeps the fetched values on disk and serves them when the
instance cannot be reached. **It writes secret values to disk in plaintext**,
giving back the one property the direct path otherwise has over SOPS-at-rest,
so it is off by default — that choice should be made, not inherited.

It is usually worth making. Without it, a host that reboots during an instance
outage comes up without the secrets its services need, and one outage becomes an
outage of everything downstream. With it, the same reboot serves values that may
be stale, and the agent prints a loud `DEGRADED` line on every run that used the
cache, because a fleet quietly running on month-old secrets is the failure this
could otherwise produce silently.

`packages.nixfisical-agent` is the host half: the same source as `nixfisical`
without the operator CLI, and without the `sops` and `git` closure that wrapping
it would drag onto every host (219 MiB against 468 MiB). The module picks it by
default. It also carries `nixfisical-keyring-install` — see
[The keyring](#the-keyring), which is the same split for the same reason.

## The keyring

Every other command in this tool projects *out* of SOPS: SOPS holds the value,
Infisical gets a copy, the host gets a copy. `nixfisical keyring` is the one
place that runs the other way, and it runs the other way because it has to. The
thing it started as was the estate's **age key** — the key SOPS files are
encrypted to — and an age key cannot arrive in a SOPS file, because it is what
opens SOPS files.

So the instance holds it, exactly one project holds it, and that project's
access list is the whole security boundary.

```sh
# Operator, once per estate. Reads ~/.ssh/sops-age.key unless told otherwise
# (or $SOPS_AGE_KEY_FILE), creates the `keyring` project if it is missing, and
# stores the key alongside where it should land on a host.
nixfisical --url https://infisical.example.com keyring push jeirslab \
  --install-path /var/lib/sops-nix/key.txt \
  --install-owner root --install-group root --install-mode 0400

# An SSH key. The type is sniffed; --type says it out loud when you want the
# error to be specific. The sidecar .pub is worth passing: the comment is what
# makes the key identifiable in an authorized_keys a year from now.
nixfisical --url https://infisical.example.com keyring push laptop-deploy \
  --from-file ~/.ssh/id_ed25519 --public-from-file ~/.ssh/id_ed25519.pub \
  --install-path /home/alex/.ssh/id_ed25519 \
  --install-owner alex --install-group users

# Any time. Who can read them, and is that still only you?
nixfisical --url https://infisical.example.com keyring audit
```

`push` is **create-only**. If `PRIVATE_KEY` is already there it refuses and
names the public half currently stored, so you can see which key you were about
to strand before you pass `--replace`. Validation happens before anything is
created — an age key against its bech32 checksum, an SSH key by parsing its
`openssh-key-v1` container — so a truncated paste fails before a project exists.

Up to eight values go in, under `/<name>` in the `prod` environment:

| value             | what it is                                           |
| ----------------- | ---------------------------------------------------- |
| `KEY_TYPE`        | `age` or `ssh`                                       |
| `PRIVATE_KEY`     | the key file, verbatim                               |
| `PUBLIC_KEY`      | age recipients, or the SSH public line               |
| `KEY_PATH`        | where the private half goes on a host                |
| `KEY_OWNER`       | who owns it there                                    |
| `KEY_GROUP`       |                                                      |
| `KEY_MODE`        | refused unless owner-only, whatever the type         |
| `PUBLIC_KEY_PATH` | where the `.pub` goes — SSH only                     |

Placement travels with the key on purpose: a host that knows where to put it
needs no per-host configuration beyond its name, and moving a key file becomes
one `push --replace` rather than a deploy.

### Why SSH keys are here and not in a certificate feature

Infisical had an SSH certificate authority. It was **removed from the product**
— migration `20260729150000_drop-ssh-and-ai-mcp-tables` drops every `ssh_*`
table, and that migration predates the version this repo pins. Marketing pages
and older docs still describe it; they are stale. What replaced it, PAM and the
SSH dynamic-secret provider, lives under `ee/` behind the same licence gate that
already blocks groups.

So on a self-hosted instance an SSH key is not a certificate operation. It is a
secret with a placement policy — which is exactly what a keyring entry already
was, so `--type ssh` is the whole feature rather than a second subsystem.

What a type changes is narrow, and lives in `nixfisical/material.py`: how the
material is validated, how its public half is derived, and what it defaults to
on disk. Push, audit and install do not branch on it.

Both validators are **pure Python**, which is a requirement rather than a
preference: the host runs the minimal build, which carries no `age` and no
`ssh-keygen`, and the host is exactly where a mangled key must be caught — it is
about to be written over the one that works. It pays off twice for SSH, because
the public half of an OpenSSH private key sits in cleartext *inside* the private
file, ahead of the encrypted section. A passphrase-protected key can therefore
have its `.pub` derived without the passphrase and without shelling out. `age`
has no equivalent, which is why `age-keygen -y` is authoritative there and the
`# public key:` comment is only a fallback the summary tells you it used.

### The keyring project must not appear in the manifest

`sync-access` grants every group a manifest names access to every project that
manifest names. There is no per-project opt-out. Add the keyring to a manifest
and the estate's master key is handed to everyone in that group, silently and
successfully.

`keyring audit` is what notices. It warns on any group at all (naming the
manifest as the usual cause), on any human who is not the superadmin, and on
the superadmin being absent. Host identities are not flagged — they are the
point. It exits 0 with warnings, so it is a thing to read, not a gate.

Infisical project roles do not scope to folders without a licensed custom role,
so **one keyring project is one blast radius**: an identity that can read one
key in it can read every key in it. Multiple estates want multiple projects,
not multiple folders.

### Pulling it onto a host

```sh
nixfisical-keyring-install --name jeirslab \
  --url https://infisical.example.com \
  --organization-id "$ORG" \
  --client-id-file /run/secrets/infisical/client_id \
  --client-secret-file /run/secrets/infisical/client_secret
```

A separate binary, not a `nixfisical` subcommand, and that is a security
property rather than packaging convenience: a host that could *push* to the
keyring could replace the key the entire estate is encrypted to. The minimal
build (`packages.nixfisical-agent`) deletes the operator CLI and keeps this,
which it can do because the pull half shells out to nothing.

What lands is decided by the entry: `KEY_TYPE` picks the validator, `KEY_PATH`
and `KEY_MODE` the private half, and for an SSH entry the public half is written
beside it at `PUBLIC_KEY_PATH`. `--path` moves both, together — splitting a key
pair across two directories fails later and somewhere else.

**The circularity, and how to cut it.** The host needs a credential to reach
Infisical; that credential normally arrives by sops-nix; sops-nix needs the age
key this command is fetching. The way out is to not use the estate key for that
first step:

```nix
sops.age.sshKeyPaths = [ "/etc/ssh/ssh_host_ed25519_key" ];
```

That derives a per-host age identity from a key the host generated itself, with
no help from anyone. Encrypt one small per-host file to it holding nothing but
the universal-auth credential from `provision-host --project keyring`, and the
host can then pull the *central* key and decrypt everything else normally. The
estate key is never a bootstrap input.

**What the host is trusting.** The install path comes from the instance, which
means a compromised instance can tell a root process where to write. The
mitigations are real but worth stating rather than assuming: the path must be
absolute, contain no `..` and no NUL; the mode must not be group- or
world-readable, for any type; and the command **refuses to overwrite any
existing file that is not itself a key of the declared type**. That last one is
what turns the `/etc/shadow` case into a loud refusal instead of an outage. It
applies to the `.pub` too — a world-readable file at an instance-chosen path is
a working attack on a host that never touches the private key at all. `--path`
overrides the stored location locally, and the summary says when it did.

The one thing the instance does **not** choose is the mode of the public half.
That comes from the type table, so no value the keyring holds can talk a host
into writing a world-readable private key.

There is deliberately no `--expect-recipient`. Checking the fetched
`PUBLIC_KEY` against the fetched `PRIVATE_KEY` proves nothing when an attacker
who can change one can change the other; it would read like a guarantee and be
theatre.

## The developer agent

The two paths above are for machines an operator owns. This one is for the
laptop, and it is a different problem: nothing there reboots on a schedule, and
a `.env` file that quietly went stale is a developer running yesterday's
credentials against today's instance and filing a bug about it.

So `homeManagerModules.agent` is a daemon. It wraps **upstream's** Go binary
(`pkgs.infisical`), which has a template engine this repo does not reimplement,
and runs it as a `systemd.user` service that polls and re-renders.

```nix
programs.nixfisical.agent = {
  enable = true;
  address = "https://infisical.example.com";
  auth = {
    clientIdFile = "${config.home.homeDirectory}/.config/infisical/client-id";
    clientSecretFile = "${config.home.homeDirectory}/.config/infisical/client-secret";
  };

  projects.work = {
    projectId = "3a1e0c2e-1f4b-4f5e-9f1d-2b7c8e5a9d10";
    environment = "dev";

    templates.api = {
      dotenv.enable = true;
      dotenv.secretPath = "/backend";
      destination = "${config.home.homeDirectory}/src/api/.env";
      onChange = "systemctl --user try-restart api-dev.service";
    };

    templates.nginx = {
      source = ./templates/dev-nginx.conf.tmpl;
      destination = "${config.home.homeDirectory}/.config/dev-nginx.conf";
      mode = "0644";
    };
  };
};
```

**Home-manager only, deliberately.** A polling daemon is the right answer on a
laptop and the wrong one on a server, where a secret changing under a running
process should be a restart the operator ordered. There is no NixOS counterpart
and adding one would be a mistake — that machine wants `nixosModules.inject`.

**Projects are the grouping because that is what makes a template short.** A
`dotenv` template inherits its project's `projectId` and `environment` instead
of repeating them, so a second folder from the same project is three lines.

### Templates

A template is a Go `text/template`, evaluated by the agent against the live
instance. It contains coordinates, not values — which is why it is safe in the
Nix store, and why the rendered output is the only place a secret appears.

Three ways to supply one, and exactly one per template:

- `source = ./foo.tmpl` — a real file. Reach for this. A template that does
  anything beyond a flat dump has conditionals in it, and those belong under
  version control rather than in a Nix string.
- `content = "..."` — inline, for the small cases.
- `dotenv.enable = true` — the flat dump, generated for you.

The last is `lib.mkDotenvTemplate`, which is also exported on its own:

```nix
content = nixfisical.lib.mkDotenvTemplate {
  projectId = "3a1e0c2e-…";
  environment = "dev";
  secretPath = "/backend";
};
```

It is exported precisely because the escape hatch is a file you write, and the
dotenv case should not be the one thing you cannot start from. Emit it, read
it, edit it into whatever your project actually needs.

All three reach the agent as `source-path` — inline content is written to the
store and the path handed over. A Go template is whitespace-significant (a
dotenv file's trailing newline decides whether some parsers see the last pair),
and a YAML block scalar is the wrong place to argue about trailing whitespace.
It also means both forms are one code path, so a bug in either is a bug in
both.

### What this module fixes about the agent

Three upstream behaviours the module handles, because each is silent when it
goes wrong:

**Modes.** Upstream writes rendered output with a bare `os.Create`, which
leaves a new file at 0644 minus the umask — on a shared machine, every
credential the developer has, readable by everyone. The module creates each
destination first, inside a `umask 077` subshell so there is no window at 0644,
then chmods it to the declared `mode` (0600 by default). `os.Create` truncates
an existing file without touching its mode, so that holds for every later
render. Parent directories are created with `mkdir -p`, not `install -d -m`,
because the parent of a destination is usually a source tree the developer
already owns and `install -d` would chmod it.

**`execute`, not `exec`.** The `onChange` hook's YAML key is `execute`.
Upstream's own documented example says `exec`, which does not match the struct
tag, so it unmarshals to nothing and the command silently never runs. The
`hm-agent` flake check pins the spelling.

**`$SHELL`.** The agent runs `onChange` through `$SHELL` when one is set,
falling back to `sh` — so the same string would be interpreted by bash on one
machine and fish on another. The unit pins `SHELL`, and `onChange` means one
thing.

Two upstream behaviours it does **not** paper over, because hiding them would
only move the surprise:

- `onChange` does not fire on the first render. A service that needs the file
  to exist should be ordered after this unit, not hung off the hook.
- Every template polls on its own timer, so N templates against one project is
  N times the request rate.

### Credentials

`clientIdFile` and `clientSecretFile` are `types.str`, not `types.path`, and
that is the point: a `types.path` would copy the file into the Nix store, which
for the client secret means publishing a credential to every user on the
machine. Both options are the same type so that mistake is not one character
away.

The files themselves are delivered by whatever the developer already trusts.
This module will not place them, because placing them would mean putting them
in the store.

The agent reads `INFISICAL_UNIVERSAL_AUTH_CLIENT_ID` from the environment in
preference to the file, so an exported variable silently wins over the
configuration.

## The agent surface

Three pieces, split by whether the question needs a running instance. The split
is the design: the common questions need nothing, and making them need a
process would be a worse answer to them.

**`nix build .#docs`** — every option the modules declare and every command the
CLI has, generated from the module system and the click tree. No process, no
credentials, no network, and it cannot drift from what it documents: an option
added without a description is a hole visible in the output, and a renamed one
moves in the same commit. Emits `options.{json,md}`, `commands.{json,md}` and an
`index.md`. `nixfisical docs --format json` prints the command half alone.

It is also a `check`, and the only one that evaluates every module's options
tree — every `default`, every `example`. That is a class of breakage nothing
else here would notice.

**`nix run .#mcp`** — an MCP server over stdio, for what is true of an instance
*right now*: `instance_status`, `license`, `list_projects`,
`list_secret_names`, `validate_manifest`, `sync_diff`, `access_diff`,
`keyring_audit`.

```json
{
  "mcpServers": {
    "nixfisical": {
      "command": "nix",
      "args": [
        "run", "github:jeirslab/nixfisical#mcp", "--",
        "--url", "https://infisical.example",
        "--admin-file", "secrets/infisical-admin.yaml"
      ]
    }
  }
}
```

Two properties it is built around. **No tool returns a secret value** — names,
coordinates, versions, counts and drift, never material. The enforcement is a
whitelist of the fields that come through rather than a blacklist of the ones
that do not, because a blacklist is one upstream field addition away from a
leak, and the leak would be silent and into a transcript.

And it **writes nothing** unless started with `--allow-writes`, which adds
exactly one tool. `sync_apply` then still refuses unless the caller passes the
deletion count `sync_diff` reported for the same manifest against the same
instance. `sync` prunes; a boolean confirmation is one an agent passes every
time, and a number it can only get by having looked is one it cannot.

It authenticates as `fleet-sync`, never as the superadmin, and it is removed
from the `minimal` build along with the CLI — a host does not need to be able to
answer questions about the other hosts.

The protocol is hand-written rather than taken from the official SDK. That SDK
brings pydantic, starlette, uvicorn and an SSE stack — a web server — into the
closure of a tool whose transport here is a pipe; measured at ~250 MiB
standalone, against four JSON-RPC methods. If this ever needs HTTP, resources,
prompts or sampling, that trade flips.

**`.claude/skills/operate/`** — the operating procedure: the ordering and the
blast radii. `sync` prunes; `sync` before `sync-access`; `source` decides
direction and a misspelled key reads as SOPS-owned; the keyring project must
never appear in the manifest; group creation is licence-gated. Skills load
path-qualified from a workspace root, which the other two do not — an MCP
server configured inside a repo is inert unless the session was launched there.

`AGENTS.md` at the root points at all three, for a consumer who has this as a
flake input and no checkout.

## What it does not do yet

**Folder pruning.** Secrets are pruned; empty folders are left behind.

**The developer agent has not run against a live instance.** The generated
config is checked structurally — every key in it is a Go struct tag, and a
wrong one does not fail, it unmarshals to the zero value and the agent runs
happily doing slightly less than you asked. The `hm-agent` check parses the
output with the same YAML library the agent uses and asserts the tags, the
template function call, and the modifier keys. That is not the same as having
watched it authenticate.

**Direct injection is unproven.** It evaluates, its Python is covered, and the
generated spec round-trips through the real agent binary — but nothing has run
it against a live instance on a real host, and there is no VM test. Treat the
first host as an experiment, and keep its secrets in SOPS until it has survived
a reboot.

**The keyring has not run against a live instance either.** Its Python is
covered offline — key parsing for both types, placement validation, the
create-only refusal, the audit warnings, and every refusal path in the installer
— but no real `keyring push` has happened, and no host has pulled a key with it.
The SSH public-key derivation is checked byte-for-byte against recorded
`ssh-keygen` output for plain ed25519, passphrase-protected ed25519 and RSA;
PEM-format keys (`ssh-keygen -m PEM`) are storable but cannot derive a public
half, so they need `--public-from-file`. The
`sops.age.sshKeyPaths` bootstrap above is the documented cut, not a tested one.
Do the first one by hand with a throwaway key and a host you can rebuild.

## Roadmap

- Reporting group access that exists on the instance but is not in the
  manifest. `sync-access` never revokes, so drift in that direction is
  currently invisible.
- A NixOS VM test covering bootstrap → sync → prune end to end, and one
  covering the `native` units against a live Postgres — they are currently
  verified by evaluation only.
- A NixOS VM test for the injection agent: boot with a reachable instance, boot
  with an unreachable one and no cache (must fail closed), and boot with an
  unreachable one and a cache (must come up degraded and say so).
- A NixOS module for `nixfisical-keyring-install`, so the pull is a
  `sops.age.keyFile` prerequisite unit rather than something an operator runs
  once by hand and hopes was remembered when the host is rebuilt.
- Revoking keyring access. `keyring audit` reports a group that should not be
  there; removing it is still a trip to the UI.

## Prior art

[`connerohnesorge/infisical-flake`](https://github.com/connerohnesorge/infisical-flake)
packages the Infisical backend and frontend with `buildNpmPackage` and exposes
a `services.infisical` module plus cluster/backup/monitoring modules. It has no
bootstrap or secret-sync layer — which is most of what this repo is — but it
had already answered the packaging question, and was worth reading closely
before the `native` backend here was written.

Read it, do not depend on it. Checked 2026-09-09: last modified 2025-10-08,
nixpkgs pinned to 2025-08-06, and it no longer evaluates —
`packages.x86_64-linux.backend` fails with `callPackageWith: Function called
without required argument "knex-cli"`. It also claims the same
`services.infisical` option path as this module, so importing both conflicts.

## License

MIT — see [LICENSE](LICENSE).
