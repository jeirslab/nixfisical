# Secret syncs: push what is in Infisical out to 49 other places.
#
# This direction is implemented: `nixfisical syncs` (see README, "Secrets
# Infisical pushes onward") converges a list built with `lib.mkSync` /
# `lib.mkGithubSync`, resolving `project` and `connection` by name. The
# nested `instances.<i>.projects.<p>.syncs` shape below is still the
# scaffold for the eventual configuration module; today the list is flat
# and `project` is a field. A sync is Infisical pushing onward — into AWS
# Parameter Store, into GitHub Actions secrets, into a Vercel project — on
# its own schedule, without us in the loop.
#
# The asymmetry worth noticing: everything in 40-secrets.nix runs when we run
# the reconciler. A sync runs when Infisical decides, which means the state of
# the world changes without a deploy. That is the feature. It is also why a
# sync is a much bigger commitment than it looks.
{
  infisical.instances.lab.projects.apps.syncs = {

    # -- the shape ----------------------------------------------------------
    #
    # POST /api/v1/secret-syncs/{destination}
    #
    # Required on every one of the 49: name, projectId, connectionId,
    # environment, secretPath, syncOptions, destinationConfig. There is no
    # destination where syncOptions or destinationConfig may be omitted, even
    # where destinationConfig has no properties at all — github and
    # gcp-secret-manager both require an object with nothing in it, because
    # the connection already says which repository or which GCP project.
    #
    # So: `destinationConfig = {}` is a real and correct value. It is not a
    # thing left unfinished.

    prod-to-parameter-store = {
      destination = "aws-parameter-store";

      # By name; resolved to connectionId. See 50-connections.nix.
      connectionId = "prod-aws";

      # What is being pushed: one environment, one folder, of this project.
      # A sync is not project-wide — it is path-scoped, and a second folder
      # is a second sync.
      environment = "prod";
      secretPath = "/cli-proxy";

      description = "Parameter Store mirror for the ECS task role";

      # Default true. False means the sync exists and only runs when asked,
      # via POST .../{syncId}/sync-secrets. That is the setting to start
      # with against a destination that already has content in it.
      isAutoSyncEnabled = true;

      syncOptions = {
        # The only REQUIRED field inside syncOptions, and the one that
        # decides whether the first run is safe.
        #
        #   overwrite-destination          Infisical wins. Anything at the
        #                                  destination that is not in
        #                                  Infisical is removed.
        #   import-prioritize-source       merge, Infisical wins conflicts
        #   import-prioritize-destination  merge, destination wins conflicts
        #
        # Most of the 49 destinations only accept `overwrite-destination` —
        # the import variants exist on AWS, Vercel, Netlify and a handful of
        # others, because they are the ones with an API to read the existing
        # values back. github does not; you cannot read a GitHub Actions
        # secret, so there is nothing to import.
        #
        # Which means: for most destinations, creating a sync is destructive
        # on the first run and there is no non-destructive option to choose.
        initialSyncBehavior = "import-prioritize-destination";

        # Rename on the way out. The destination's naming rules are rarely
        # ours — "/app/prod/{{secretKey}}" is the Parameter Store convention
        # and INFISICAL_ prefixes are a common house style.
        #
        # This is a mapping, so it is also a collision risk: two keys that
        # differ only in a character the schema drops become one secret at
        # the destination, and the loser is silently gone.
        keySchema = "/app/prod/{{secretKey}}";

        # Deleting a secret in Infisical stops deleting it downstream. The
        # safety valve, and the thing that turns a sync into an append-only
        # mirror. Worth setting while you are still learning what the sync
        # does.
        disableSecretDeletion = false;

        # AWS-only additions.
        keyId = "alias/aws/ssm";     # KMS key for SecureString
        tags = [                     # max 50
          { key = "estate"; value = "lab"; }
        ];
        syncSecretMetadataAsTags = false; # secretMetadata -> destination tags
      };

      # Destination-specific. Parameter Store needs a region and a path
      # prefix; both REQUIRED.
      destinationConfig = {
        region = "us-east-1";
        path = "/app/prod/";
      };
    };

    # -- the empty-config case -----------------------------------------------
    #
    # github's destinationConfig has no properties. The repository is a
    # property of the connection, not of the sync. Still required as an
    # object.
    #
    # Note initialSyncBehavior here accepts exactly one value. The schema is
    # an enum of one, so this is not a default you may omit — it is the only
    # thing you are allowed to say.
    prod-to-github-actions = {
      destination = "github";
      connectionId = "lab-github";
      environment = "prod";
      secretPath = "/ci";
      syncOptions = {
        initialSyncBehavior = "overwrite-destination"; # the only value
        keySchema = "{{secretKey}}";
        disableSecretDeletion = false;
      };
      destinationConfig = { };
    };

    # -- instance-to-instance ------------------------------------------------
    #
    # Infisical syncing to another Infisical. The federation primitive; see
    # 93-federation.nix. destinationConfig names the remote project,
    # environment and path, so this is genuinely a full address on the far
    # side.
    #
    # keySchema is explicitly documented as "Not supported for Infisical
    # syncs" — the key is the key. Sensible, and worth stating because the
    # field is present in the schema regardless.
    prod-to-upstream = {
      destination = "external-infisical";
      connectionId = "upstream";
      environment = "prod";
      secretPath = "/shared";
      syncOptions.initialSyncBehavior = "import-prioritize-destination";
      destinationConfig = {
        projectId = "…remote project id…";
        environment = "prod";
        secretPath = "/imported/lab";
      };
    };
  };

  # -- non-CRUD operations --------------------------------------------------
  #
  # Not declarable. Recorded so the capability is not rediscovered:
  #
  #   POST .../{syncId}/sync-secrets     run it now
  #   POST .../{syncId}/import-secrets   pull the destination back IN,
  #                                      ?importBehavior=prioritize-source
  #                                      |prioritize-destination
  #   POST .../{syncId}/remove-secrets   unwind: delete everything this sync
  #                                      put there, leave the sync
  #
  # import-secrets is the one that matters for declaration: it creates
  # secrets in the project that the declaration did not declare. They will
  # look like drift to a prune pass and get deleted. Mark them `unmanaged`
  # in 40-secrets.nix, or scope the sync to a folder the declaration does not
  # otherwise own.

  # -- the other 46 destinations --------------------------------------------
  #
  # 1password aws-parameter-store aws-secrets-manager azure-app-configuration
  # azure-devops azure-entra-id-scim azure-key-vault bitbucket camunda
  # checkly chef circleci cloud-66 cloudflare-pages cloudflare-workers
  # databricks daytona devin digital-ocean-app-platform external-infisical
  # flyio gcp-secret-manager github gitlab hashicorp-vault hasura-cloud
  # heroku humanitec laravel-forge netlify northflank oci-vault
  # octopus-deploy ona ovh qovery railway render rundeck snowflake spacelift
  # supabase teamcity terraform-cloud travis-ci trigger-dev vercel windmill
  # zabbix
  #
  # Note what is NOT there: Kubernetes. Infisical will not write a Secret
  # object into a namespace through this API. That direction is the
  # Kubernetes Operator, a separate product that reads from Infisical, and it
  # is not declarable here. See 92-kubernetes.nix.
  #
  # cloudflare-workers adds `syncNonSecretBindings` to syncOptions. The rest
  # of the per-destination variation is destinationConfig, and all of it is
  # generated into nix/lib/generated/syncs.nix rather than written out.
}
