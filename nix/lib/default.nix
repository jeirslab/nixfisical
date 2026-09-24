# nixfisical/nix/lib — the declaration + manifest layer.
#
# Two halves:
#
#   mkInfisical   attached to a `sops.secrets.<key>` entry, marks that secret
#                 developer-facing and says where in Infisical it lands.
#   manifestOf    walks a fleet's `nixosConfigurations` and collects every
#                 such annotation into a flat, deduped manifest.
#
# plus an escape hatch for secrets no host declares:
#
#   mkExportOnly  names a (sopsFile, sopsKey) directly, with no host behind it.
#   mkLiteral     a value that is not a secret (a port, a hostname), carried
#                 in the manifest itself and pushed beside the secrets.
#   manifestFrom  the general form of manifestOf — hosts and export-only
#                 entries merged into one manifest.
#
# The manifest is STRUCTURE ONLY — it names SOPS keys, never values. Nothing
# decrypted ever enters the Nix store. The `nixfisical sync` CLI takes this
# manifest plus your age key and does the decryption at run time, on the
# operator's machine.
#
# Each entry also carries `source`, naming which side owns its value. The
# manifest therefore describes both directions at once: `sync` reads the
# `source = "sops"` entries and pushes them up, `import` reads the
# `source = "infisical"` ones and writes them down. One declaration, two
# commands, and no secret that both of them write.
{ lib }:

rec {
  # Attach to a secret to export it. `project` is the hard access boundary in
  # Infisical, so it is the one field with no default — choosing it is a
  # security decision and should be explicit at every call site.
  #
  #   sops.secrets."services/bitcoin/rpc_password" = {
  #     infisical = nixfisical.lib.mkInfisical {
  #       project = "bitcoin-nodes";
  #       folder  = "/mainnet";
  #       groups  = [ "developers" ];
  #     };
  #   };
  #
  # `source` names which side owns the VALUE, and defaults to the direction
  # this repo was built around: SOPS is the truth, Infisical is the view.
  # Setting it to "infisical" reverses that for one secret -- `sync` stops
  # writing the value and `import` starts writing the SOPS file. See the
  # option's description in nix/modules/export.nix for the full contract.
  mkInfisical =
    { project
    , folder ? "/"
    , environment ? "prod"
    , name ? null
    , groups ? [ ]
    , source ? "sops"
    }: {
      inherit project folder environment name groups source;
    };

  # Export a secret that NO host declares.
  #
  # `mkInfisical` rides on a `sops.secrets` entry, which means the exported set
  # is exactly the set some machine consumes. That is the right default and
  # should stay the common case. It breaks down for a credential whose only
  # consumer is a person or an agent's client: mailbox passwords that the mail
  # host verifies as hashes and must never hold in plaintext, an API token
  # handed out but never deployed. Declaring those on a host to make the export
  # work is a lie in the fleet's own manifest, and sops-nix would then
  # materialise the credential on a machine with no use for it.
  #
  # So name the file and key directly:
  #
  #   nixfisical.lib.mkExportOnly {
  #     sopsFile = ./secrets/mail-clients.yaml;
  #     sopsKey  = "mail.engine_password";
  #     project  = "platform";
  #     folder   = "/mail";
  #   }
  #
  # The result is an ordinary manifest entry with `hosts = [ ]`. It is
  # validated, deduped and PRUNED exactly like a host-derived one: drop the
  # declaration and the next sync deletes the secret from Infisical. The
  # sopsFile must still be decryptable by whoever runs the sync — the entry
  # asserts nothing about who can read it, only where it goes.
  # `source` works here exactly as it does on `mkInfisical`, and is arguably
  # more at home: a credential with no host behind it is often one a person
  # was handed rather than one the estate generated, which is the case
  # `source = "infisical"` describes. Note that an export-only entry has no
  # NixOS module validating the field, so `assertManifest` is the only thing
  # standing between a typo here and a manifest the CLI silently treats as
  # SOPS-owned.
  mkExportOnly =
    { sopsFile
    , sopsKey
    , project
    , folder ? "/"
    , environment ? "prod"
    , name ? null
    , groups ? [ ]
    , source ? "sops"
    }: {
      inherit sopsKey project folder environment groups source;
      sopsFile = toString sopsFile;
      host = null;
      name = if name != null then name else lib.last (lib.splitString "/" sopsKey);
    };

  # A value that is NOT a secret, exported beside the ones that are.
  #
  # Every rendered .env needs the port next to the password and the host next
  # to the token, and none of those are secrets -- they are in the fleet
  # manifest, in DNS, in the world-readable store. Forcing them into a SOPS
  # file to get them exported would be the accommodation `mkExportOnly` warns
  # against, in the other direction. So a literal names its value directly:
  #
  #   nixfisical.lib.mkLiteral {
  #     project     = "bitcoin-nodes";
  #     environment = "mainnet";
  #     folder      = "/bitcoind";
  #     name        = "BITCOIND_RPC_PORT";
  #     value       = 8332;                 # toString'd; keep it a string or an int
  #     groups      = [ "developers" ];
  #   }
  #
  # It is an ordinary manifest entry: validated, deduped on its coordinate,
  # PRUNED when the declaration goes. `sync` pushes it like a SOPS value with
  # the decryption step skipped; `import` never claims it. `sopsKey` is a
  # synthetic identity so the dedupe and every error message have a name to
  # use -- it is not a lookup path and no file is ever opened for it.
  #
  # The value lands in the manifest, and the manifest lands in the store. That
  # is fine for a port and a hostname and is exactly why `assertManifest`
  # refuses a `value` on any entry that is not a literal.
  #
  # `host` is provenance only, as everywhere else in the manifest: pass the
  # host the value describes so the table shows it, or leave it null.
  mkLiteral =
    { project
    , name
    , value
    , folder ? "/"
    , environment ? "prod"
    , groups ? [ ]
    , host ? null
    }: {
      inherit project folder environment groups name host;
      value = toString value;
      source = "literal";
      sopsFile = null;
      sopsKey = "literal:${project}/${environment}${folder}:${name}";
    };

  # nixosConfigurations -> [ manifestEntry ]
  #
  # The host-only form, kept as the public entry point it has always been.
  manifestOf = nixosConfigurations: manifestFrom { inherit nixosConfigurations; };

  # { nixosConfigurations, extraSecrets } -> [ manifestEntry ]
  #
  # An entry carries its OWN `sopsFile`. sops-nix already tracks this per
  # secret (`sops.secrets.<k>.sopsFile`, defaulting to `sops.defaultSopsFile`),
  # so a fleet whose secrets are split across several encrypted files exports
  # correctly without the sync tool having to guess. Emitting it here is what
  # lets the CLI stay file-agnostic.
  #
  # `extraSecrets` is a list of `mkExportOnly` results. They join the same
  # pipeline as host-derived entries rather than being appended afterwards, so
  # the dedupe below sees both: an export-only entry naming a (sopsFile,
  # sopsKey) some host also exports collapses into that host's entry instead of
  # becoming a second entry racing it to the same destination.
  manifestFrom =
    { nixosConfigurations ? { }
    , extraSecrets ? [ ]
    }:
    let
      perHost = lib.mapAttrsToList
        (host: node:
          lib.mapAttrsToList
            (attr: sec:
              let
                e = sec.infisical or null;
                # The attribute name is NOT the lookup path. sops-nix resolves a
                # value with `sops.secrets.<attr>.key`, which merely *defaults*
                # to <attr>; declaring `key` is the normal way to give a secret
                # a descriptive name on the host while the encrypted file stays
                # flat. Reading <attr> here produced a manifest that rendered,
                # validated and then failed mid-sync against a real instance
                # with "sops key 'cli-proxy/api_key' not found (no 'cli-proxy'
                # under <root>)" -- the file's key was `api_key`.
                sopsKey = sec.key or attr;
              in
              if e == null then null else {
                inherit sopsKey;
                sopsFile =
                  if (sec.sopsFile or null) != null
                  then toString sec.sopsFile
                  else null;
                inherit host;
                inherit (e) project environment folder groups;
                # `or` rather than `inherit`: the module gives `source` a
                # default, so a config that went through it always has one.
                # This is for the caller who hands `manifestFrom` a hand-built
                # attrset -- a test, or a consumer assembling entries without
                # the module. Absent means the direction this repo started
                # with, which is also what keeps older callers working.
                source = e.source or "sops";
                # Default the Infisical-side name to the last segment of the
                # SOPS key: "services/bitcoin/rpc_password" -> "rpc_password".
                name = if e.name != null then e.name else lib.last (lib.splitString "/" sopsKey);
              })
            (node.config.sops.secrets or { }))
        nixosConfigurations;

      # Host-derived first, so that on a (sopsFile, sopsKey) collision the fold
      # below keeps the host's destination and the export-only entry only
      # contributes its (empty) host list.
      flat = lib.filter (x: x != null) (lib.flatten perHost) ++ extraSecrets;

      # Dedupe on (sopsFile, sopsKey), not sopsKey alone: the same key path can
      # legitimately exist in two different encrypted files (e.g. a per-network
      # split), and collapsing those would silently drop one of them. Hosts
      # that share an entry are unioned into `hosts`.
      identity = e: "${toString e.sopsFile}#${e.sopsKey}";

      # `host = null` (an export-only entry) contributes nothing to `hosts`,
      # leaving it empty. That empty list is the manifest's record that the
      # secret is exported on nobody's behalf — the CLI treats `hosts` as
      # provenance, never as a target.
      byKey = lib.foldl'
        (acc: e:
          let
            k = identity e;
            prev = acc.${k} or null;
            hosts = lib.optional (e.host != null) e.host;
          in
          acc // {
            ${k} =
              if prev == null
              then (removeAttrs e [ "host" ]) // { inherit hosts; }
              else prev // { hosts = lib.unique (prev.hosts ++ hosts); };
          })
        { }
        flat;
    in
    lib.sort (a: b: identity a < identity b) (lib.attrValues byKey);

  # The Go template that renders a whole Infisical folder as a dotenv file.
  #
  #   programs.nixfisical.agent.projects.work.templates."env" = {
  #     content = nixfisical.lib.mkDotenvTemplate {
  #       projectId = "abc-123";
  #       environment = "dev";
  #     };
  #     destination = "${config.home.homeDirectory}/src/work/.env";
  #   };
  #
  # The agent module's `dotenv.enable` calls this for you; it is exported
  # because the whole point of the raw-`source` escape hatch is that a real
  # template is a file you write, and the dotenv case should not be the one
  # thing you cannot start from. Emit it, read it, then edit it into whatever
  # your project actually needs.
  #
  # `text/template`, evaluated by the agent against the live instance -- so
  # this string is a *program*, and nothing in it is a value. It is safe in
  # the store.
  #
  # The `{{-` trimming is not cosmetic. Without it every directive leaves the
  # newline that terminated it, and a dotenv file with a blank line between
  # each pair is one that some parsers read as ending at the first one.
  mkDotenvTemplate =
    { projectId
    , environment ? "dev"
      # Infisical's own name for what this repo calls a folder. Kept as
      # `secretPath` because that is the argument name in the template
      # function, and this string is going to be read next to Infisical's
      # docs rather than next to `mkInfisical`.
    , secretPath ? "/"
      # Pull sub-folders in too, flattened. Off, because two folders holding
      # the same key name collapse into one line and which one wins is not
      # something this template can tell you.
    , recursive ? false
      # Resolve `${OTHER_SECRET}` references before writing. On, matching the
      # agent's own default -- a reference that reaches a .env file unresolved
      # is read by the application as a literal.
    , expandSecretReferences ? true
    }:
    let
      modifier = builtins.toJSON {
        inherit recursive expandSecretReferences;
      };
    in
    ''
      {{- with listSecrets "${projectId}" "${environment}" "${secretPath}" `${modifier}` }}
      {{- range . }}
      {{ .Key }}={{ .Value }}
      {{- end }}
      {{- end }}
    '';

  # Fail the evaluation on manifest problems that would only surface as a
  # confusing HTTP 4xx halfway through a sync. Cheap to run at `nix flake
  # check` time; `nixfisical validate` repeats these against the rendered
  # JSON for anyone consuming the manifest outside Nix.
  # -- secret syncs ---------------------------------------------------------
  #
  # A sync is Infisical pushing one folder of one environment onward, on its
  # own schedule. Entries use the API's own field names (see
  # examples/60-syncs.nix); `project` and `connection` are NAMES the
  # reconciler resolves to ids. `nixfisical syncs` converges them, after
  # `sync` has created the projects they live in.
  mkSync =
    { name
    , project
    , destination
    , connection
    , environment ? "prod"
    , secretPath ? "/"
    , description ? null
    , isAutoSyncEnabled ? true
    , syncOptions ? { }
    , destinationConfig ? { }
    , app ? null              # app-connection kind when it differs from `destination`
    }: {
      inherit name project destination connection environment secretPath
        isAutoSyncEnabled syncOptions destinationConfig;
    } // lib.optionalAttrs (description != null) { inherit description; }
      // lib.optionalAttrs (app != null) { inherit app; };

  # GitHub Actions secrets of one repository. `overwrite-destination` is the
  # only initialSyncBehavior GitHub accepts (there is no API to read Actions
  # secrets back), so it is not a parameter.
  mkGithubSync =
    { owner
    , repo
    , project
    , connection
    , name ? "${owner}/${repo}"
    , environment ? "prod"
    , secretPath ? "/"
    , keySchema ? "{{secretKey}}"
    , disableSecretDeletion ? false
    , isAutoSyncEnabled ? true
    , description ? null
    }:
    mkSync {
      inherit name project connection environment secretPath isAutoSyncEnabled description;
      destination = "github";
      syncOptions = {
        initialSyncBehavior = "overwrite-destination";
        inherit keySchema disableSecretDeletion;
      };
      destinationConfig = { scope = "repository"; inherit owner repo; };
    };

  assertSyncs = syncs:
    let
      missing = field: lib.filter (e: !(e ? ${field}) || e.${field} == "" || e.${field} == null) syncs;
      badPath = lib.filter (e: !(lib.hasPrefix "/" (e.secretPath or "/"))) syncs;
      badEnv = lib.filter
        (e: builtins.match "[a-z0-9-]+" (e.environment or "") == null)
        syncs;
      noBehaviour = lib.filter
        (e: !((e.syncOptions or { }) ? initialSyncBehavior))
        syncs;
      coordinate = e: "${e.project or "?"}:${e.name or "?"}";
      dup =
        let
          counts = lib.foldl'
            (acc: e: acc // { ${coordinate e} = (acc.${coordinate e} or 0) + 1; })
            { }
            syncs;
        in
        lib.filter (e: counts.${coordinate e} > 1) syncs;
      err = msg: entries:
        lib.optional (entries != [ ])
          "${msg}: ${lib.concatMapStringsSep ", " coordinate entries}";
      problems =
        err "sync without a name" (missing "name")
        ++ err "sync without a project" (missing "project")
        ++ err "sync without a destination" (missing "destination")
        ++ err "sync without a connection" (missing "connection")
        ++ err "secretPath must start with /" badPath
        ++ err "environment must be a slug" badEnv
        ++ err "syncOptions.initialSyncBehavior is required" noBehaviour
        ++ err "sync declared twice" dup;
    in
    if problems == [ ] then syncs
    else throw ("nixfisical: invalid syncs declaration:\n  " + lib.concatStringsSep "\n  " problems);

  # Per-project metadata for `sync --projects`: `{ <name> = { description =
  # "…"; }; }`. Checked here so a typo'd field or an over-long description
  # fails at `nix flake check` rather than as a 400 halfway through a sync.
  assertProjects = projects:
    let
      bad = lib.filterAttrs
        (name: meta:
          !(builtins.isAttrs meta)
          || (lib.any (k: k != "description") (builtins.attrNames meta))
          || ((meta.description or "") != null && !(builtins.isString (meta.description or "")))
          || (builtins.stringLength (meta.description or "") > 1024))
        projects;
    in
    if bad == { } then projects
    else throw ("nixfisical: invalid projects declaration (only `description`, a string of at most 1024 chars): "
      + lib.concatStringsSep ", " (builtins.attrNames bad));

  assertManifest = manifest:
    let
      isLiteral = e: (e.source or "sops") == "literal";
      missingFile = lib.filter (e: e.sopsFile == null && !(isLiteral e)) manifest;

      # A literal with nothing in it renders as `KEY=` and is read by every
      # dotenv parser as the empty string -- a port of "" is a bug that shows
      # up as a connection refused somewhere else. Caught here by name.
      emptyLiteral = lib.filter (e: isLiteral e && (e.value or "") == "") manifest;

      # The mirror image, and the one that matters: a `value` on anything but
      # a literal is a plaintext secret in the manifest, and the manifest is in
      # the store. `mkInfisical` and `mkExportOnly` cannot produce one, so this
      # only fires on a hand-built entry -- which is exactly where it should.
      strayValue = lib.filter (e: !(isLiteral e) && (e ? value)) manifest;
      badEnv = lib.filter
        (e: builtins.match "[a-z0-9-]+" e.environment == null)
        manifest;
      badFolder = lib.filter (e: !(lib.hasPrefix "/" e.folder)) manifest;

      # `sops.secrets.<n>.key = ""` is sops-nix for "the whole file", which has
      # no single value to mirror. Caught here because an empty sopsKey reaches
      # the CLI as a lookup that cannot be phrased, let alone explained.
      emptyKey = lib.filter (e: e.sopsKey == "") manifest;

      # The one field whose wrong value is silent rather than loud. A bad
      # `project` 404s and a bad `environment` is caught above, but an entry
      # reading `source = "Infisical"` (or "remote", or "pull") is a
      # well-formed manifest that every tool here will treat as SOPS-owned --
      # so the next `sync` pushes the local value over the instance's, which
      # is the exact accident the field exists to prevent. The module's enum
      # catches this for host-derived entries; nothing catches it for
      # `mkExportOnly` or a hand-built one, so it is caught here.
      badSource = lib.filter
        (e: !(lib.elem (e.source or "sops") [ "sops" "infisical" "literal" ]))
        manifest;

      # Two entries writing the same Infisical coordinate: one wins, and which
      # one depends on manifest ordering. `nixfisical validate` catches this
      # too, but only once the manifest has been rendered and handed to the
      # CLI. It is worth catching a step earlier now that `mkExportOnly` lets a
      # `name` be typed by hand rather than derived from a key some host
      # already declares -- a typo there aims two secrets at one destination.
      coordinate = e: "${e.project}/${e.environment}${e.folder}:${e.name}";
      dupDest =
        let
          counts = lib.foldl'
            (acc: e: acc // { ${coordinate e} = (acc.${coordinate e} or 0) + 1; })
            { }
            manifest;
        in
        lib.filter (e: counts.${coordinate e} > 1) manifest;

      err = msg: entries:
        lib.optional (entries != [ ])
          "${msg}: ${lib.concatMapStringsSep ", " (e: e.sopsKey) entries}";

      # Same, for problems where the sopsKey is itself the thing that is wrong
      # and so cannot name the offender.
      errBy = msg: entries:
        lib.optional (entries != [ ])
          "${msg}: ${lib.concatMapStringsSep ", " (e: "${e.project}${e.folder}:${e.name}") entries}";

      problems =
        (err "secrets with no sopsFile (set sops.defaultSopsFile or a per-secret sopsFile)" missingFile)
        ++ (err "environment slugs must match [a-z0-9-]+" badEnv)
        ++ (err "folder paths must be absolute (start with /)" badFolder)
        ++ (errBy "whole-file secrets (key = \"\") cannot be exported; name a key" emptyKey)
        ++ (errBy "two secrets declared into the same Infisical destination" dupDest)
        ++ (err "source must be \"sops\", \"infisical\" or \"literal\"" badSource)
        ++ (errBy "literal values must not be empty" emptyLiteral)
        ++ (errBy "only a literal may carry a `value`; a SOPS-owned value belongs in its encrypted file" strayValue);
    in
    if problems == [ ]
    then manifest
    else throw "nixfisical: invalid Infisical manifest:\n  - ${lib.concatStringsSep "\n  - " problems}";
}
