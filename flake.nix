{
  description = "Declarative Infisical for NixOS — server module, self-healing bootstrap, and a sops-driven secret reconciler";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    let
      # The declaration/manifest layer is pure — it only needs `lib`, so it is
      # available without a system and callable from a consumer's flake before
      # any package is built.
      nixfisicalLib = import ./nix/lib { lib = nixpkgs.lib; };
    in
    {
      lib = nixfisicalLib;

      nixosModules = {
        default = ./nix/modules;
        # Run a self-hosted Infisical instance.
        server = ./nix/modules/server.nix;
        # Add `sops.secrets.<key>.infisical` so secrets can be annotated for
        # export. Import this on every host you want to export from.
        export = ./nix/modules/export.nix;
        # EXPERIMENTAL, and not in `default` for that reason. Fetch this host's
        # secrets from the instance at boot instead of through sops-nix. A
        # different trust model, not a better one -- see the module header.
        inject = ./nix/modules/inject.nix;
      };

      homeManagerModules = {
        default = ./nix/modules/hm-agent.nix;
        # Upstream's Infisical agent as a `systemd.user` service: templates
        # rendered from the instance into the developer's own tree, re-rendered
        # when a secret changes. Deliberately home-manager only -- a polling
        # daemon is the right answer on a laptop and the wrong one on a server,
        # where `nixosModules.inject` fetches once at boot instead.
        agent = ./nix/modules/hm-agent.nix;
      };

      overlays.default = final: prev:
        let
          # Not exposed as an attribute: it is a version pin and two helper
          # strings, not a package, and a consumer's nixpkgs has no use for it.
          infisicalSource = final.callPackage ./nix/pkgs/infisical-source.nix { };
        in
        {
          nixfisical = final.callPackage ./nix/pkgs/nixfisical.nix { };

          # The same source, built for the hosts rather than the operator: the
          # agent alone, with neither sops nor git in its closure. A fleet that
          # injects directly would otherwise carry the operator's tooling on
          # every machine.
          nixfisical-agent = final.callPackage ./nix/pkgs/nixfisical.nix {
            minimal = true;
          };

          # The API, the web UI, and the two joined so the API serves the UI.
          # Separate because the API is useful alone and the UI is cheap to
          # rebuild while the API is not -- see infisical-standalone.nix.
          infisical-backend = final.callPackage ./nix/pkgs/infisical-backend.nix {
            inherit infisicalSource;
          };
          infisical-frontend = final.callPackage ./nix/pkgs/infisical-frontend.nix {
            inherit infisicalSource;
          };
          infisical-standalone = final.callPackage ./nix/pkgs/infisical-standalone.nix {
            inherit infisicalSource;
          };
          # `bump-infisical` is deliberately absent: it rewrites this repo's own
          # source and is only meaningful from a checkout, so it is a flake app
          # rather than something a consumer's nixpkgs should carry.
        };

      # Render a fleet's manifest as a flake app:
      #
      #   packages.infisical-manifest =
      #     nixfisical.mkManifestApp {
      #       inherit pkgs;
      #       nixosConfigurations = self.nixosConfigurations;
      #     };
      #
      #   nix run .#infisical-manifest            # JSON (feeds `nixfisical sync`)
      #   nix run .#infisical-manifest -- table   # human review
      #
      # The JSON is baked at eval time and contains no decrypted values —
      # only SOPS key paths and their routing.
      # `extraSecrets` is a list of `lib.mkExportOnly` results: secrets to
      # export that no host declares. See the comment on `mkExportOnly` for
      # when that is the honest thing to do rather than a shortcut.
      mkManifestApp = { pkgs, nixosConfigurations, extraSecrets ? [ ], syncs ? [ ], validate ? true }:
        let
          raw = nixfisicalLib.manifestFrom { inherit nixosConfigurations extraSecrets; };
          manifest = if validate then nixfisicalLib.assertManifest raw else raw;
          json = builtins.toJSON manifest;
          # The outbound half (`nixfisical syncs`): a second, smaller manifest
          # rather than a second kind of entry in the first, so every existing
          # consumer of the secrets manifest keeps reading a list of secrets.
          syncsJson = builtins.toJSON (if validate then nixfisicalLib.assertSyncs syncs else syncs);
        in
        pkgs.writeShellApplication {
          name = "infisical-manifest";
          runtimeInputs = [ pkgs.jq pkgs.util-linux ];
          text = ''
            M=${pkgs.lib.escapeShellArg json}
            S=${pkgs.lib.escapeShellArg syncsJson}
            case "''${1:-json}" in
              json)
                printf '%s' "$M" | jq '.'
                ;;
              syncs)
                printf '%s' "$S" | jq '.'
                ;;
              table)
                {
                  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                    PROJECT ENV FOLDER NAME GROUPS "SOPS FILE" "SOPS KEY"
                  printf '%s' "$M" | jq -r '
                    .[] | [.project, .environment, .folder, .name,
                           (.groups | join(",")), .sopsFile, .sopsKey] | @tsv'
                } | column -t -s "$(printf '\t')"
                echo ""
                echo "exported secrets: $(printf '%s' "$M" | jq 'length')"
                ;;
              *)
                echo "usage: infisical-manifest [json|table|syncs]" >&2
                exit 1
                ;;
            esac
          '';
        };

      # The same manifest, pushed:
      #
      #   packages.infisical-sync = nixfisical.mkSyncApp {
      #     inherit pkgs;
      #     nixosConfigurations = self.nixosConfigurations;
      #     url = "https://infisical.example.org";
      #   };
      #
      #   nix run .#infisical-sync -- --dry-run   # licence table, then what would change
      #   nix run .#infisical-sync                # converge
      #
      # `sync`, then `sync-access`. The ordering is not stylistic: `sync-access`
      # grants a group access to a project, so the project has to exist, and
      # `sync` is what creates it -- run the other way round, a first
      # convergence grants nothing and reports no error.
      #
      # Under `--dry-run` the full `license` table is printed in front of both.
      # Only under `--dry-run`: it is twenty-five lines of reference material
      # that does not change between runs, and `sync-access` prints the one line
      # of it that does ("licence: none ...") on every run regardless. Putting
      # it on the converge path would mean an operator reading past two screens
      # of unchanged output to reach the two lines that say what happened, which
      # is how output stops being read at all.
      #
      # Nothing is lost by leaving it off the converge path. It is a report, not
      # a gate -- an unlicensed instance is the normal case and `sync` skips
      # what the plan forbids on its own -- and it is not the early
      # authentication check it looks like either, because `sync` logs in before
      # it writes anything, so a missing age key or an expired sync identity
      # fails there just as cleanly.
      #
      # THIS PRUNES. `sync` deletes secrets the manifest no longer declares, so
      # deleting a `mkInfisical` annotation deletes the secret from Infisical on
      # the next run. That is the declarative contract working, and it is still
      # worth knowing before the first unattended run. `--dry-run` names every
      # deletion.
      #
      # What it deliberately will not do is create a group. That needs
      # `--create-missing-groups`, which writes to Infisical's Postgres behind
      # the API, and a hammer that size should be swung by hand, once, not
      # folded into the command an operator runs after every change.
      #
      # Runs on the operator's machine, not on the instance: the decryption is
      # local and uses the operator's age key, which no host has.
      mkSyncApp =
        { pkgs
        , nixosConfigurations
        , url
          # Secrets to export that no host declares; see `lib.mkExportOnly`.
          # They are pruned like any other entry: drop one here and the next
          # sync deletes it from Infisical.
        , extraSecrets ? [ ]
        , syncs ? [ ]
        , validate ? true
        , adminFile ? "secrets/infisical-admin.yaml"
          # The age identity to decrypt with, if SOPS_AGE_KEY_FILE is not
          # already set. Null leaves sops to its own default,
          # ~/.config/sops/age/keys.txt.
          #
          # Worth setting for an estate that keeps a per-repo key, because the
          # failure it prevents does not look like what it is. Unset, sops
          # reports a missing keyring and a keyring holding the wrong key
          # identically -- twenty lines of "Recovery failed because no master
          # key was able to decrypt the file", which reads like a corrupt file
          # and means neither. A flake app is run from outside any dev shell by
          # definition, so it is the likeliest place to meet that.
        , ageKeyFile ? null
          # The humans `sync-access` puts on every project it manages. Null
          # means "read it from the admin file", which works for an INSTANCE
          # admin file and cannot work for a PER-ORG one: `add-org`
          # deliberately omits the admin block, so there is no email in there to
          # read. A consumer syncing into its own organization on a shared
          # instance is exactly that case and must set this.
          #
          # Set it to `false` to pass --no-operator instead, accepting projects
          # whose only member is the sync machine identity -- which is to say,
          # projects no human can see. That is a real choice for an unattended
          # estate and a bad surprise anywhere else.
          #
          # Four shapes, because on an unlicensed instance this is not just how
          # the operator keeps visibility, it is the ONLY ungated way to give
          # any human access at all -- group creation needs a licence, this
          # does not. So it has to express more than one person:
          #
          #   operator = "admin@example.org";          one person, default role
          #   operator = false;                        nobody
          #   operator = [ "a@example.org" { email = "dev@example.org";
          #                                  role  = "viewer"; } ];
          #
          # A list element is either a bare email (taking --operator-role) or
          # `{ email; role; }`. The attrset is rendered to the `EMAIL:ROLE`
          # form the CLI parses, so the parsing lives in exactly one place;
          # a bare string is passed through, which means a literal
          # "dev@example.org:viewer" also works if you prefer it.
          #
          # Everyone named must ALREADY be a member of the organization. This
          # adds a person to a project; it does not invite them to the org.
        , operator ? null
          # Role for any operator that does not name one. Left null to use the
          # CLI's own default (`admin`), which is right for the person who
          # administers the instance and wrong for everyone else -- which is
          # why a developer should carry their own `role` rather than this
          # being lowered fleet-wide.
        , operatorRole ? null
          # Defaults to this flake's own build so a consumer needs neither the
          # overlay nor a matching nixpkgs. Pass `pkgs.nixfisical` if you have it.
        , nixfisical ? self.packages.${pkgs.stdenv.hostPlatform.system}.nixfisical
        }:
        let
          manifestApp = self.mkManifestApp {
            inherit pkgs nixosConfigurations extraSecrets syncs validate;
          };
          inherit (pkgs) lib;
          # An operator entry -> the `EMAIL[:ROLE]` string the CLI parses.
          # Rejecting an attrset without `email` here rather than emitting
          # "null:viewer" and letting the CLI complain: the Nix call site is
          # where the typo is, and a consumer reading a shell error out of a
          # generated script has a much worse time finding it.
          operatorArg = entry:
            if builtins.isString entry then entry
            else if builtins.isAttrs entry then
              (if !(entry ? email) then
                throw
                  ("nixfisical.mkSyncApp: an `operator` attrset needs an "
                  + "`email` field; got ${builtins.toJSON entry}")
              else if entry ? role && entry.role != null
              then "${entry.email}:${entry.role}"
              else entry.email)
            else
              throw ("nixfisical.mkSyncApp: `operator` list elements must be "
              + "strings or { email; role ? null; } attrsets");
          # Only `sync-access` takes these; `sync` would reject them, which is
          # why they are baked in here rather than left to the caller's "$@".
          accessArgs =
            (if operator == null then ""
            else if operator == false then " --no-operator"
            else
              lib.concatMapStrings
                (entry: " --operator ${lib.escapeShellArg (operatorArg entry)}")
                (if builtins.isList operator then operator else [ operator ]))
            + lib.optionalString (operatorRole != null)
              " --operator-role ${lib.escapeShellArg operatorRole}";
        in
        pkgs.writeShellApplication {
          name = "infisical-sync";
          # coreutils for `mktemp`. writeShellApplication only prepends to the
          # ambient PATH, so leaving it out works everywhere it is tried and
          # depends on the caller's environment anyway.
          runtimeInputs = [ manifestApp nixfisical pkgs.coreutils ];
          text = ''
            # --dry-run is the only flag, because it is the only one both
            # subcommands accept. Anything else belongs on `nixfisical` itself,
            # where the help text says which subcommand it applies to.
            case "''${1-}" in
              ""|--dry-run) ;;
              *)
                echo "usage: infisical-sync [--dry-run]" >&2
                exit 1
                ;;
            esac

            ${pkgs.lib.optionalString (ageKeyFile != null) ''
            # `:=` and not `=`: an operator who set SOPS_AGE_KEY_FILE meant it,
            # and a dev shell that already exports one keeps winning.
            : "''${SOPS_AGE_KEY_FILE:=${ageKeyFile}}"
            if [ -f "$SOPS_AGE_KEY_FILE" ]; then
              export SOPS_AGE_KEY_FILE
            else
              # Warn, but do not export and do not exit. SOPS_AGE_KEY and the
              # ssh-key paths are still live, so an operator with a working
              # setup that is not this one must not be broken by a default --
              # and pointing the variable at a file that is not there would
              # narrow sops' search rather than widen it.
              echo "infisical-sync: no age identity at $SOPS_AGE_KEY_FILE;" \
                   "falling back to sops' own search" >&2
            fi
            ''}
            # A file rather than a pipe: both subcommands read the manifest, and
            # `-` can only be consumed once.
            manifest=$(mktemp)
            trap 'rm -f "$manifest"' EXIT
            infisical-manifest json > "$manifest"

            if [ "''${1-}" = "--dry-run" ]; then
              nixfisical --url ${pkgs.lib.escapeShellArg url} \
                --admin-file ${pkgs.lib.escapeShellArg adminFile} license
              echo ""
            fi

            nixfisical --url ${pkgs.lib.escapeShellArg url} \
              --admin-file ${pkgs.lib.escapeShellArg adminFile} \
              sync --manifest "$manifest" "$@"
            echo ""
            ${pkgs.lib.optionalString (syncs != [ ]) ''
            # Outbound syncs, after the projects they live in exist.
            syncs_manifest=$(mktemp)
            trap 'rm -f "$manifest" "$syncs_manifest"' EXIT
            infisical-manifest syncs > "$syncs_manifest"
            nixfisical --url ${pkgs.lib.escapeShellArg url} \
              --admin-file ${pkgs.lib.escapeShellArg adminFile} \
              syncs --manifest "$syncs_manifest" "$@"
            echo ""
            ''}
            nixfisical --url ${pkgs.lib.escapeShellArg url} \
              --admin-file ${pkgs.lib.escapeShellArg adminFile} \
              sync-access --manifest "$manifest"${accessArgs} "$@"
          '';
        };
    }
    // flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        nixfisical = pkgs.callPackage ./nix/pkgs/nixfisical.nix { };
        nixfisical-agent = pkgs.callPackage ./nix/pkgs/nixfisical.nix {
          minimal = true;
        };
        infisicalSource = pkgs.callPackage ./nix/pkgs/infisical-source.nix { };
        infisical-backend = pkgs.callPackage ./nix/pkgs/infisical-backend.nix {
          inherit infisicalSource;
        };
        infisical-frontend = pkgs.callPackage ./nix/pkgs/infisical-frontend.nix {
          inherit infisicalSource;
        };
        infisical-standalone = pkgs.callPackage ./nix/pkgs/infisical-standalone.nix {
          inherit infisicalSource infisical-backend infisical-frontend;
        };
        bump-infisical = pkgs.callPackage ./nix/pkgs/bump-infisical.nix { };

        # The offline half of the agent surface: every option this flake
        # declares and every command its CLI has, generated from the module
        # system and the click tree rather than written beside them. See
        # nix/docs/default.nix for why this is a derivation and not a server.
        docs = pkgs.callPackage ./nix/docs { inherit nixpkgs nixfisical; };
      in
      {
        packages = {
          inherit nixfisical nixfisical-agent bump-infisical docs
            infisical-backend infisical-frontend infisical-standalone;
          default = nixfisical;
        };

        apps.default = {
          type = "app";
          program = "${nixfisical}/bin/nixfisical";
        };

        apps.bump-infisical = {
          type = "app";
          program = "${bump-infisical}/bin/bump-infisical";
          meta.description = "Bump the pinned Infisical release and its hashes";
        };

        # The online half of the agent surface. An app rather than only a
        # binary in `packages` because this is what a consumer's `.mcp.json`
        # names: `nix run github:jeirslab/nixfisical#mcp -- --url ...`, with no
        # checkout and nothing installed. See pkgs/nixfisical/nixfisical/mcp.py
        # for what it will and will not answer — it never returns a secret
        # value, and it writes nothing without `--allow-writes`.
        apps.mcp = {
          type = "app";
          program = "${nixfisical}/bin/nixfisical-mcp";
          meta.description = "MCP server over a live Infisical instance (read-only by default)";
        };

        devShells.default = pkgs.mkShell {
          packages = [
            nixfisical
            pkgs.sops
            pkgs.age
            pkgs.jq
            # The upstream CLI, for poking at an instance by hand.
            pkgs.infisical
            (pkgs.python3.withPackages (ps: [ ps.click ps.httpx ps.pyyaml ]))
          ];
          shellHook = ''
            echo "nixfisical dev shell — 'nixfisical --help' for the CLI."
          '';
        };

        checks = {
          package = nixfisical;

          # The docs derivation asserts its own emptiness cases, so building it
          # is the check. Worth having in `checks` rather than leaving it to
          # `packages`: it is the only thing that evaluates every module's
          # options tree, including every `default` and `example`, which is a
          # class of breakage nothing else here would notice.
          inherit docs;

          # Build the sync app. There is nothing to assert about the result --
          # the point is that `writeShellApplication` runs shellcheck and that
          # the two helper functions resolve at all, neither of which happens
          # anywhere else: `mkSyncApp` is a top-level function, so `nix flake
          # check` never reaches it, and the first consumer to call it is the
          # first thing to find out it does not evaluate.
          #
          # Which is how it went. Writing this cost one unbound variable
          # (`mkManifestApp` where `self.mkManifestApp` was meant -- the
          # function is an output attribute, not a `let` binding) and one
          # `mktemp` resolved off the caller's PATH rather than the closure.
          #
          # An empty fleet on purpose. The manifest's *content* is checked
          # above; this checks the script that carries it, and an empty one
          # builds the same script.
          sync-app = self.mkSyncApp {
            inherit pkgs;
            nixosConfigurations = { };
            url = "https://infisical.invalid";
            # Set, because the `ageKeyFile` block is the only conditionally
            # emitted shell in the app: left at its null default it renders to
            # the empty string, and a check that builds the app without it is a
            # check that shellcheck never reads the branch most likely to be
            # wrong. The value is a shell expression on purpose -- that is the
            # contract, and this is what exercises it.
            ageKeyFile = "\${XDG_CONFIG_HOME:-$HOME/.config}/sops/age/keys.txt";
          };

          # Evaluate the home-manager agent module standalone and assert the
          # YAML it hands the upstream binary.
          #
          # Standalone because home-manager is not an input here and should
          # not become one for a module that only borrows two of its options.
          # The stub below declares exactly those two, which is also the
          # module's whole contract with home-manager -- if that grows, this
          # check is what notices.
          #
          # The thing being defended is narrow and worth naming: every key in
          # that YAML is a Go struct tag, and a wrong one does not fail. It
          # unmarshals to the zero value and the agent runs happily doing
          # slightly less than you asked. `exec` for `execute` is the version
          # of this that upstream's own documentation ships.
          hm-agent =
            let
              hmStub = { lib, ... }: {
                options.systemd.user.services = lib.mkOption {
                  type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
                  default = { };
                };
                options.assertions = lib.mkOption {
                  type = lib.types.listOf lib.types.unspecified;
                  default = [ ];
                };
              };

              eval = extra: (nixpkgs.lib.evalModules {
                modules = [
                  ./nix/modules/hm-agent.nix
                  hmStub
                  { _module.args.pkgs = pkgs; }
                ] ++ extra;
              }).config;

              base = {
                enable = true;
                address = "https://infisical.invalid";
                auth.clientIdFile = "/home/dev/.config/infisical/client-id";
                auth.clientSecretFile = "/home/dev/.config/infisical/client-secret";
              };

              good = eval [{
                programs.nixfisical.agent = base // {
                  projects.work = {
                    projectId = "abc-123";
                    templates = {
                      backend = {
                        dotenv.enable = true;
                        dotenv.secretPath = "/backend";
                        destination = "/home/dev/src/api/.env";
                        onChange = "true";
                      };
                      # A raw template, to pin that both forms reach the agent
                      # the same way and that a template without `onChange`
                      # emits no `execute` block at all rather than an empty
                      # one -- an empty command is a shell invocation of "",
                      # every polling interval, forever.
                      other = {
                        content = "static\n";
                        destination = "/home/dev/src/api/other.conf";
                        mode = "0644";
                      };
                    };
                  };
                };
              }];

              # Every assertion that would fire, for a config. Home-manager
              # evaluates these itself; here they are just a list, so the
              # check reads the list.
              failing = c: nixpkgs.lib.filter (a: !a.assertion) c.assertions;

              twoSources = failing (eval [{
                programs.nixfisical.agent = base // {
                  projects.work = {
                    projectId = "abc-123";
                    templates.both = {
                      dotenv.enable = true;
                      content = "also this\n";
                      destination = "/home/dev/.env";
                    };
                  };
                };
              }]);

              sharedDestination = failing (eval [{
                programs.nixfisical.agent = base // {
                  projects.work = {
                    projectId = "abc-123";
                    templates.a = { content = "a\n"; destination = "/home/dev/.env"; };
                    templates.b = { content = "b\n"; destination = "/home/dev/.env"; };
                  };
                };
              }]);

              noTemplates = failing (eval [{
                programs.nixfisical.agent = base;
              }]);

              # An enabled module with a valid config must produce a clean
              # assertion list. Without this the three checks above pass just
              # as well against a module that asserts on everything.
              goodIsClean = failing good == [ ];

              execStart = good.systemd.user.services.nixfisical-agent.Service.ExecStart;
            in
            pkgs.runCommand "nixfisical-hm-agent-check"
              { nativeBuildInputs = [ pkgs.yq-go ]; }
              (nixpkgs.lib.optionalString (!goodIsClean) ''
                echo "a valid agent config produced failing assertions:" >&2
                echo ${nixpkgs.lib.escapeShellArg
                  (builtins.toJSON (map (a: a.message) (failing good)))} >&2
                exit 1
              '' + nixpkgs.lib.optionalString (twoSources == [ ]) ''
                echo "a template setting both dotenv and content was accepted" >&2
                exit 1
              '' + nixpkgs.lib.optionalString (sharedDestination == [ ]) ''
                echo "two templates sharing a destination were accepted" >&2
                exit 1
              '' + nixpkgs.lib.optionalString (noTemplates == [ ]) ''
                echo "an enabled agent with no templates was accepted" >&2
                exit 1
              '' + ''
                execstart=${nixpkgs.lib.escapeShellArg execStart}
                case "$execstart" in
                  *" agent --config "*) ;;
                  *) echo "ExecStart is not an agent invocation: $execstart" >&2
                     exit 1 ;;
                esac
                config="''${execstart##* --config }"

                get() { yq -o=json -I=0 "$1" "$config"; }

                check() {
                  actual=$(get "$1")
                  if [ "$actual" != "$2" ]; then
                    echo "$1: expected $2, got $actual" >&2
                    exit 1
                  fi
                }

                check '.infisical.address' '"https://infisical.invalid"'
                check '.infisical.exit-after-auth' 'false'
                # Absent, not null: `maxRetries` is unset, and an emitted
                # `retry-strategy` with zero retries is not the same as
                # leaving upstream's strategy alone.
                check '.infisical | has("retry-strategy")' 'false'

                check '.auth.type' '"universal-auth"'
                check '.auth.config.client-id' '"/home/dev/.config/infisical/client-id"'
                check '.auth.config.client-secret' '"/home/dev/.config/infisical/client-secret"'
                # Underscores. Upstream's one inconsistent struct tag, and a
                # hyphenated spelling here would silently never remove it.
                check '.auth.config.remove_client_secret_on_read' 'false'

                check '.sinks | length' '0'
                check '.templates | length' '2'

                env=$(get '.templates[] | select(.destination-path == "/home/dev/src/api/.env")')
                other=$(get '.templates[] | select(.destination-path == "/home/dev/src/api/other.conf")')

                [ "$(printf '%s' "$env" | yq -o=json -I=0 '.config.execute.command')" = '"true"' ] \
                  || { echo "dotenv template lost its execute.command" >&2; exit 1; }
                [ "$(printf '%s' "$env" | yq -o=json -I=0 '.config.execute.timeout')" = '30' ] \
                  || { echo "dotenv template lost its execute.timeout" >&2; exit 1; }
                [ "$(printf '%s' "$env" | yq -o=json -I=0 '.config.polling-interval')" = '"60s"' ] \
                  || { echo "dotenv template lost its polling-interval" >&2; exit 1; }
                [ "$(printf '%s' "$other" | yq -o=json -I=0 '.config | has("execute")')" = 'false' ] \
                  || { echo "a template with no onChange emitted an execute block" >&2; exit 1; }

                # Both forms are source-path; neither is inlined into the YAML.
                for t in "$env" "$other"; do
                  [ "$(printf '%s' "$t" | yq -o=json -I=0 'has("source-path")')" = 'true' ] \
                    || { echo "a template was not handed over as source-path" >&2; exit 1; }
                done

                dotenv=$(printf '%s' "$env" | yq -o=json -I=0 -r '.source-path')
                # The generated template is the contract with Infisical's
                # template engine: the function name, the argument order, and
                # the modifier's JSON keys are all theirs, and all silent when
                # wrong -- a misspelled modifier key unmarshals to `false`.
                grep -qF 'listSecrets "abc-123" "dev" "/backend"' "$dotenv" \
                  || { echo "dotenv template does not call listSecrets as expected:" >&2
                       cat "$dotenv" >&2; exit 1; }
                grep -qF '{"expandSecretReferences":true,"recursive":false}' "$dotenv" \
                  || { echo "dotenv template modifier is not what Infisical parses:" >&2
                       cat "$dotenv" >&2; exit 1; }
                # No blank line between pairs. Without the `{{-` trimming each
                # directive leaves its own newline behind and some dotenv
                # parsers stop at the first blank line.
                grep -qF '{{- range . }}' "$dotenv" \
                  || { echo "dotenv template lost its whitespace trimming" >&2; exit 1; }

                [ "$(cat "$(printf '%s' "$other" | yq -o=json -I=0 -r '.source-path')")" = 'static' ] \
                  || { echo "inline content did not survive the round trip" >&2; exit 1; }

                echo ok > $out
              '');

          # Evaluate the export module standalone and assert the manifest
          # walk produces what we expect: the name defaulting, the per-secret
          # sopsFile, the host union, and the exclusion of unannotated
          # secrets. Catches regressions in nix/lib without needing a full
          # NixOS system or sops-nix.
          manifest = pkgs.runCommand "nixfisical-manifest-check" { } (
            let
              # Minimal stand-in for the sops-nix options the manifest walk
              # reads, so the check stays free of a sops-nix input. Same
              # merge trick the export module uses.
              #
              # `key` must be modelled, and modelled with sops-nix's default of
              # the attribute name. An earlier stub declared only `sopsFile`,
              # so every secret looked like one whose key was its attribute
              # name -- the check went green on a manifest that could not
              # resolve a single value against a real instance.
              sopsFileStub = { lib, ... }: {
                options.sops.secrets = lib.mkOption {
                  type = lib.types.attrsOf (lib.types.submodule ({ name, ... }: {
                    options.sopsFile = lib.mkOption {
                      type = lib.types.nullOr (lib.types.either lib.types.str lib.types.path);
                      default = null;
                    };
                    options.key = lib.mkOption {
                      type = lib.types.str;
                      default = name;
                    };
                  }));
                };
              };

              mkHost = host: secrets: {
                config = (nixpkgs.lib.evalModules {
                  modules = [
                    ./nix/modules/export.nix
                    sopsFileStub
                    { sops.secrets = secrets; }
                  ];
                }).config;
              };

              shared = {
                "services/api/token" = {
                  sopsFile = "/fleet/secrets/api.yaml";
                  infisical = nixfisicalLib.mkInfisical {
                    project = "apps";
                    folder = "/api";
                    groups = [ "developers" ];
                  };
                };
              };

              configurations = {
                alpha = mkHost "alpha" (shared // {
                  "dbs/main/password" = {
                    sopsFile = "/fleet/secrets/dbs.yaml";
                    infisical = nixfisicalLib.mkInfisical {
                      project = "databases";
                      name = "MAIN_PASSWORD";
                    };
                  };
                  # Explicit `key`: the attribute is a descriptive host-side
                  # name, the encrypted file is flat. sopsKey must follow the
                  # key ("api_key"), not the attribute.
                  "cli-proxy/api_key" = {
                    sopsFile = "/fleet/secrets/cli-proxy.yaml";
                    key = "api_key";
                    infisical = nixfisicalLib.mkInfisical {
                      project = "apps";
                      folder = "/cli-proxy";
                      name = "CLI_PROXY_API_KEY";
                      groups = [ "developers" ];
                    };
                  };
                  # Same, with the Infisical name left to default. It must
                  # derive from the resolved key ("mealie"), not the attribute
                  # -- which is why the attribute ends in something else.
                  "infra-db/mealie_pw" = {
                    sopsFile = "/fleet/secrets/infra-db.yaml";
                    key = "mealie";
                    infisical = nixfisicalLib.mkInfisical {
                      project = "databases";
                      folder = "/mealie";
                    };
                  };
                  # Owned by the instance, not by SOPS. Identical in every
                  # other respect to the entries above -- which is the point:
                  # it is an ordinary manifest entry that `sync` declines to
                  # write the value of and `import` writes into SOPS. If the
                  # field ever stops reaching the manifest, `sync` starts
                  # pushing the local copy over the IdP's and the only symptom
                  # is an OIDC login that stops working.
                  "services/grafana/oidc_secret" = {
                    sopsFile = "/fleet/secrets/platform.yaml";
                    infisical = nixfisicalLib.mkInfisical {
                      project = "platform";
                      folder = "/grafana";
                      name = "OIDC_CLIENT_SECRET";
                      source = "infisical";
                    };
                  };
                  # Unannotated: must never appear in the manifest.
                  "internal/root_key" = { sopsFile = "/fleet/secrets/dbs.yaml"; };
                });
                beta = mkHost "beta" shared;
              };

              extraSecrets = [
                # No host declares this one, and none should: a mailbox
                # password is verified by the mail host as a hash and read in
                # plaintext only by a person. It must still land with the same
                # shape as every other entry, `hosts` empty.
                (nixfisicalLib.mkExportOnly {
                  sopsFile = "/fleet/secrets/mail-clients.yaml";
                  sopsKey = "mail.engine_password";
                  project = "platform";
                  folder = "/mail";
                })
                # Redundant with alpha+beta's annotation: same file, same key,
                # same destination. Must collapse into that one entry and leave
                # its host provenance intact, not append a second entry racing
                # it to the same coordinate.
                (nixfisicalLib.mkExportOnly {
                  sopsFile = "/fleet/secrets/api.yaml";
                  sopsKey = "services/api/token";
                  project = "apps";
                  folder = "/api";
                  groups = [ "developers" ];
                })
              ];

              manifest = nixfisicalLib.assertManifest
                (nixfisicalLib.manifestFrom {
                  nixosConfigurations = configurations;
                  inherit extraSecrets;
                });

              # Two entries aimed at one Infisical coordinate from different
              # files: nothing dedupes them, so `assertManifest` is the only
              # thing standing between a typo and a secret that silently loses.
              dupCaught = !(builtins.tryEval
                (builtins.deepSeq
                  (nixfisicalLib.assertManifest (nixfisicalLib.manifestFrom {
                    extraSecrets = [
                      (nixfisicalLib.mkExportOnly {
                        sopsFile = "/fleet/secrets/a.yaml";
                        sopsKey = "pw";
                        project = "platform";
                        name = "PW";
                      })
                      (nixfisicalLib.mkExportOnly {
                        sopsFile = "/fleet/secrets/b.yaml";
                        sopsKey = "other";
                        project = "platform";
                        name = "PW";
                      })
                    ];
                  }))
                  true)).success;

              actual = builtins.toJSON manifest;

              # Ordered by the dedupe identity ("<sopsFile>#<sopsKey>"), so
              # api.yaml sorts ahead of dbs.yaml.
              expected = builtins.toJSON [
                {
                  environment = "prod";
                  folder = "/api";
                  groups = [ "developers" ];
                  hosts = [ "alpha" "beta" ];
                  name = "token";
                  project = "apps";
                  sopsFile = "/fleet/secrets/api.yaml";
                  sopsKey = "services/api/token";
                  source = "sops";
                }
                {
                  environment = "prod";
                  folder = "/cli-proxy";
                  groups = [ "developers" ];
                  hosts = [ "alpha" ];
                  name = "CLI_PROXY_API_KEY";
                  project = "apps";
                  sopsFile = "/fleet/secrets/cli-proxy.yaml";
                  sopsKey = "api_key";
                  source = "sops";
                }
                {
                  environment = "prod";
                  folder = "/";
                  groups = [ ];
                  hosts = [ "alpha" ];
                  name = "MAIN_PASSWORD";
                  project = "databases";
                  sopsFile = "/fleet/secrets/dbs.yaml";
                  sopsKey = "dbs/main/password";
                  source = "sops";
                }
                {
                  environment = "prod";
                  folder = "/mealie";
                  groups = [ ];
                  hosts = [ "alpha" ];
                  name = "mealie";
                  project = "databases";
                  sopsFile = "/fleet/secrets/infra-db.yaml";
                  sopsKey = "mealie";
                  source = "sops";
                }
                {
                  environment = "prod";
                  folder = "/mail";
                  groups = [ ];
                  hosts = [ ];
                  name = "mail.engine_password";
                  project = "platform";
                  sopsFile = "/fleet/secrets/mail-clients.yaml";
                  sopsKey = "mail.engine_password";
                  source = "sops";
                }
                # The one entry the instance owns. Its presence here is what
                # pins `source` to the manifest: drop the field from the
                # plumbing and this entry reads "sops" like every other one,
                # and `sync` starts overwriting a value it did not author.
                {
                  environment = "prod";
                  folder = "/grafana";
                  groups = [ ];
                  hosts = [ "alpha" ];
                  name = "OIDC_CLIENT_SECRET";
                  project = "platform";
                  sopsFile = "/fleet/secrets/platform.yaml";
                  sopsKey = "services/grafana/oidc_secret";
                  source = "infisical";
                }
              ];
            in
            if actual != expected then
              throw ''
                nixfisical manifest check failed.
                  expected: ${expected}
                  actual:   ${actual}
              ''
            else if !dupCaught then
              throw ''
                nixfisical manifest check failed: assertManifest accepted two
                entries declared into the same Infisical destination.
              ''
            else "echo ok > $out"
          );
        };

        formatter = pkgs.nixpkgs-fmt;
      });
}
