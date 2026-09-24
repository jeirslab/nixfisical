"""HTTP client for the Infisical REST API.

Scope note: this covers the endpoints the Ansible role used, plus the four
``adopt`` needs to log in as a human and find its way to an organization.
Nothing else. Infisical's API is large and versioned inconsistently
(``/api/v1``, ``/api/v2`` and ``/api/v3`` all appear below, and that is not a
typo -- it is what the server exposes). Keeping the surface small keeps the
blast radius of an upstream change small.

Two behaviours carried over from the role deserve explanation:

* **Tolerated conflict statuses.** Several "create" endpoints are not
  idempotent and do not agree on how to report "that already exists".
  Environments answer 400, 409 *or* 422 depending on version; folders answer
  400 or 409. Rather than pre-flighting with a list call for every object, we
  create optimistically and pass the acceptable statuses in ``allow_status``.
* **POST-then-PATCH upsert for secrets.** There is no upsert endpoint. The
  role created and, on conflict, updated. We do the same in
  :meth:`InfisicalClient.upsert_secret`.

Nothing in this module logs or embeds a secret value. Error bodies are
truncated and are only ever from failing calls, but note that a failing
secret write can echo back the payload -- see ``_redact``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

import httpx

__all__ = ["InfisicalError", "InfisicalClient", "UniversalAuthCredentials"]

# Trusted-IP allowlist applied to the machine identity. The Ansible role used
# an open allowlist because the identity is reachable only over the estate's
# private network and every consumer's egress IP is dynamic; narrowing this is
# a follow-up that needs the network model, not a one-line change here.
_OPEN_TRUSTED_IPS: list[dict[str, str]] = [
    {"ipAddress": "0.0.0.0/0"},
    {"ipAddress": "::/0"},
]

# Response bodies are only surfaced on failure, but a failed secret write can
# reflect the submitted payload back at us. Redact the obvious carriers before
# anything reaches an exception message.
_SECRET_FIELD_NAMES = frozenset(
    {
        "secretValue",
        "clientSecret",
        "password",
        "accessToken",
        "token",
        "privateKey",
        "encryptedPrivateKey",
    }
)

_BODY_TRUNCATE_AT = 600

# Sent on every request. Two reasons it is set explicitly rather than left to
# httpx's default:
#
# * ``POST /api/v3/auth/login`` *rejects* a request with no ``User-Agent`` at
#   all -- the handler's first statement is a throw. httpx does send a default,
#   so this is belt and braces, but a hard server-side requirement should not
#   rest on a client library's default staying what it is today.
# * Infisical records the user agent on the session and in the audit log.
#   ``python-httpx/0.27.0`` in an audit trail says nothing; this says which
#   tool logged in.
_USER_AGENT = "nixfisical"


class InfisicalError(RuntimeError):
    """An Infisical API call failed.

    Carries the HTTP status and a truncated, redacted response body so an
    operator can tell a 401 from a 422 without opening a proxy log.
    """

    def __init__(self, message: str, *, status: int | None = None, body: str = "") -> None:
        self.status = status
        self.body = body
        detail = f" (HTTP {status})" if status is not None else ""
        if body:
            detail += f": {body}"
        super().__init__(f"{message}{detail}")


@dataclass(frozen=True)
class UniversalAuthCredentials:
    """The client id / client secret pair for a Universal Auth identity.

    ``__repr__`` is overridden so a stray ``print`` or a traceback frame
    rendering local variables cannot leak the secret half.
    """

    client_id: str
    client_secret: str

    def __repr__(self) -> str:  # pragma: no cover - defensive formatting
        return f"UniversalAuthCredentials(client_id={self.client_id!r}, client_secret=<redacted>)"


def _redact(value: Any) -> Any:
    """Recursively blank out fields whose names imply secret material."""
    if isinstance(value, Mapping):
        return {
            key: ("<redacted>" if key in _SECRET_FIELD_NAMES else _redact(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _safe_body(response: httpx.Response) -> str:
    """Render a response body for an error message: redacted and truncated.

    Only structured JSON is echoed, because only there can we redact by field
    name. A non-JSON body -- an HTML error page from a reverse proxy, say --
    is described but never quoted: we cannot reason about what it contains,
    and the request that produced it carried a secret value.
    """
    try:
        rendered = repr(_redact(response.json()))
    except ValueError:
        content_type = response.headers.get("content-type", "unknown")
        rendered = (
            f"<non-JSON body withheld: {content_type},"
            f" {len(response.content)} bytes>"
        )
    rendered = " ".join(rendered.split())
    if len(rendered) > _BODY_TRUNCATE_AT:
        rendered = rendered[:_BODY_TRUNCATE_AT] + "...<truncated>"
    return rendered


class InfisicalClient:
    """Minimal Infisical API client.

    ``token`` may be set after construction -- bootstrap creates the client
    unauthenticated, receives a superadmin token from ``/admin/bootstrap``, and
    then keeps using the same connection pool.
    """

    def __init__(
        self,
        base_url: str,
        *,
        token: str | None = None,
        verify: bool = True,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.verify = verify
        self._client = httpx.Client(
            base_url=self.base_url,
            verify=verify,
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": _USER_AGENT},
        )

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "InfisicalClient":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- plumbing ----------------------------------------------------------

    def _headers(self, *, authenticated: bool) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if authenticated:
            if not self.token:
                raise InfisicalError("no access token available; authenticate first")
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: Mapping[str, Any] | None = None,
        params: Mapping[str, Any] | None = None,
        authenticated: bool = True,
        allow_status: Iterable[int] = (),
        description: str | None = None,
    ) -> tuple[int, dict[str, Any]]:
        """Issue a request and return ``(status, parsed_body)``.

        Any 2xx status, plus anything in ``allow_status``, is returned to the
        caller; everything else raises :class:`InfisicalError`. ``allow_status``
        is how the tolerate-already-exists cases are expressed -- the caller
        inspects the returned status to tell "created" from "existed".

        A body that is not JSON parses to ``{}`` rather than raising, because
        several Infisical endpoints answer 200 with an empty body.
        """
        what = description or f"{method} {path}"
        try:
            response = self._client.request(
                method,
                path,
                json=dict(json) if json is not None else None,
                params=dict(params) if params is not None else None,
                headers=self._headers(authenticated=authenticated),
            )
        except httpx.HTTPError as exc:
            raise InfisicalError(f"{what} failed: {exc}") from exc

        allowed = set(allow_status)
        if not (200 <= response.status_code < 300 or response.status_code in allowed):
            raise InfisicalError(
                what, status=response.status_code, body=_safe_body(response)
            )

        try:
            payload = response.json()
        except ValueError:
            payload = {}
        if not isinstance(payload, dict):
            payload = {"data": payload}
        return response.status_code, payload

    # -- status ------------------------------------------------------------

    def status(self) -> dict[str, Any]:
        """Probe ``/api/status``.

        Used by the ``status`` command and as a readiness gate in deploy
        scripts: a freshly started Infisical answers this well before it is
        ready to be bootstrapped.
        """
        _, payload = self._request(
            "GET", "/api/status", authenticated=False, description="status probe"
        )
        return payload

    def instance_config(self) -> dict[str, Any]:
        """Probe ``/api/v1/admin/config`` -- the instance's own server settings.

        Unauthenticated, because the login page has to know whether to offer a
        signup link before anyone has logged in. The field we care about is
        ``initialized``: it is the authoritative answer to "has this instance
        been bootstrapped?", which is otherwise only knowable by trying and
        failing.

        That matters because the alternative -- inferring it from whether an
        admin file exists on the machine running this tool -- is a property of
        the *checkout*, not of the instance. The two disagree exactly when it
        is most expensive: a lost admin file reads as "fresh instance, go
        bootstrap it", and bootstrap is the one thing that cannot work there.
        """
        _, payload = self._request(
            "GET",
            "/api/v1/admin/config",
            authenticated=False,
            description="instance config probe",
        )
        return payload.get("config") or {}

    # -- bootstrap & identity ---------------------------------------------

    def bootstrap_instance(
        self, *, email: str, password: str, organization: str
    ) -> dict[str, Any]:
        """Initialise an uninitialised instance: superadmin + organization.

        This endpoint succeeds exactly once in an instance's life; a second
        call answers an error. That one-shot nature is why bootstrap.py is so
        careful about not calling it against an instance that may already be
        set up.
        """
        _, payload = self._request(
            "POST",
            "/api/v1/admin/bootstrap",
            json={
                "email": email,
                "password": password,
                "organization": organization,
            },
            authenticated=False,
            description="instance bootstrap",
        )
        return payload

    # -- superadmin login (adopt and add-org only) -------------------------
    #
    # Everything else in this module authenticates as a machine identity. These
    # exist for two jobs -- `nixfisical adopt` and `nixfisical add-org` -- both
    # of which have to act as a human superadmin exactly long enough to mint
    # the machine identity that replaces it. Nothing on the sync path calls
    # them.
    #
    # Logging in as a user is two requests, not one. `/auth/login` issues a
    # token with no organization attached, and `verifyAuth` defaults to
    # `requireOrg: true` -- so that token is rejected by almost every route,
    # including the `POST /api/v1/identities` this whole dance is for. The
    # org-scoped token comes from `/auth/select-organization`.

    def login(self, *, email: str, password: str) -> str:
        """Log in as a user with an email and password; return the access token.

        Uses ``/api/v3/auth/login``, which upstream comments as "New login route
        that doesn't use SRP". The older ``/login1`` + ``/login2`` pair speaks
        SRP, and reimplementing that here to avoid sending a password over an
        already-TLS-protected channel would be a lot of cryptography for no
        gain.

        Sets ``self.token``, but that token carries **no organization**, and
        ``verifyAuth`` defaults to requiring one -- so it opens only the few
        routes declared ``requireOrg: false``, which here means
        :meth:`list_organizations`, :meth:`current_user` and
        :meth:`select_organization`. Anything else answers 401 until
        :meth:`select_organization` has replaced it.
        """
        _, payload = self._request(
            "POST",
            "/api/v3/auth/login",
            json={"email": email, "password": password},
            authenticated=False,
            description="superadmin login",
        )
        token = payload.get("accessToken")
        if not token:
            raise InfisicalError("superadmin login returned no accessToken")
        self.token = token
        return token

    def select_organization(self, organization_id: str) -> str:
        """Exchange an org-less user token for one scoped to an organization.

        Also sets ``self.token``.

        This is where MFA is enforced -- ``/auth/login`` has no MFA branch at
        all, the check lives here. When the account requires a second factor the
        endpoint answers 200 with ``isMfaEnabled: true`` and a *challenge*
        token, not an access token, so a caller that blindly read ``token``
        would carry on with a credential that authenticates nothing. We refuse
        instead: prompting for a TOTP code belongs in an interactive tool, not
        in something that may be running from a deploy script.
        """
        _, payload = self._request(
            "POST",
            "/api/v3/auth/select-organization",
            json={"organizationId": organization_id},
            description="select organization",
        )
        if payload.get("isMfaEnabled"):
            method = payload.get("mfaMethod") or "an unknown method"
            raise InfisicalError(
                f"this account requires multi-factor authentication ({method}); "
                "nixfisical cannot complete an MFA challenge"
            )
        token = payload.get("token")
        if not token:
            raise InfisicalError("select organization returned no token")
        self.token = token
        return token

    def list_organizations(self) -> list[dict[str, Any]]:
        """Return the organizations the logged-in user belongs to.

        One of the few routes that accepts the org-less token from
        :meth:`login`, which is what makes "log in, then work out which
        organization to adopt" possible without the operator knowing an id.
        """
        _, payload = self._request(
            "GET", "/api/v1/organization/", description="list organizations"
        )
        organizations = payload.get("organizations") or []
        return [org for org in organizations if org.get("id")]

    def get_plan(self, organization_id: str) -> dict[str, Any]:
        """Return the organization's resolved licence feature set.

        ``GET /api/v1/organizations/{id}/plan``. Undocumented -- it is an ``ee``
        route and appears nowhere in the OpenAPI spec -- but it accepts
        ``AuthMode.IDENTITY_ACCESS_TOKEN``, so the sync identity can read it
        without a human session. That is the whole reason licence awareness can
        be a property of a run rather than something an operator types in.

        The route's own response schema is ``z.object({ plan: z.any() })``, so
        the shape is not promised by upstream either; :class:`~nixfisical.license.Plan`
        takes it defensively. Returns the envelope as received.
        """
        _, payload = self._request(
            "GET",
            f"/api/v1/organizations/{organization_id}/plan",
            description="read organization plan",
        )
        return payload

    def create_organization(self, name: str) -> dict[str, Any]:
        """Create an organization and return its record.

        Accepts the org-less token from :meth:`login` -- necessarily, since
        this is a route you must be able to reach before belonging to any
        organization.

        Worth stating explicitly because the neighbouring case is the opposite:
        organization creation is **not** gated behind an enterprise plan the
        way group creation is. Verified against v0.165.8, which answers 200
        here while answering 400 "Failed to create group due to plan
        restriction" to ``POST /api/v1/groups``. So ``add-org`` needs none of
        the direct-to-Postgres machinery in :mod:`nixfisical.access`.

        The caller is enrolled as a member, so the new organization shows up in
        the next :meth:`list_organizations` and :meth:`select_organization`
        accepts its id. The slug is derived from the name by the server, with a
        random suffix for uniqueness, and cannot be chosen here.
        """
        _, payload = self._request(
            "POST",
            "/api/v2/organizations",
            json={"name": name},
            description=f"create organization {name!r}",
        )
        organization = payload.get("organization") or {}
        if not organization.get("id"):
            raise InfisicalError(
                f"create organization {name!r} returned no organization id"
            )
        return organization

    def current_user(self) -> dict[str, Any]:
        """Return the logged-in user record. Used for the admin file's user id."""
        _, payload = self._request(
            "GET", "/api/v1/user", description="current user"
        )
        user = payload.get("user") or {}
        if not user.get("id"):
            raise InfisicalError("current user lookup returned no user id")
        return user

    def list_identities(self, organization_id: str) -> dict[str, str]:
        """Return a ``{identity name: identity id}`` map for the organization.

        Identity names are not unique in Infisical, so this cannot be used to
        *find* an identity reliably -- it is used to notice that a name is
        already taken before creating a second one nobody asked for.
        """
        _, payload = self._request(
            "GET",
            "/api/v1/identities",
            params={"orgId": organization_id},
            description="list identities",
        )
        memberships = payload.get("identities") or []
        found: dict[str, str] = {}
        for membership in memberships:
            identity = membership.get("identity") or {}
            if identity.get("name") and identity.get("id"):
                found[identity["name"]] = identity["id"]
        return found

    # -- identities --------------------------------------------------------

    def create_identity(
        self, *, name: str, organization_id: str, role: str = "admin"
    ) -> str:
        """Create a machine identity in the organization; return its id."""
        _, payload = self._request(
            "POST",
            "/api/v1/identities",
            json={"name": name, "organizationId": organization_id, "role": role},
            description=f"create identity {name!r}",
        )
        identity_id = payload.get("identity", {}).get("id")
        if not identity_id:
            raise InfisicalError(f"create identity {name!r} returned no identity id")
        return identity_id

    def attach_universal_auth(
        self, identity_id: str, *, token_ttl: int = 2592000
    ) -> str:
        """Attach the Universal Auth method to an identity; return its clientId.

        ``accessTokenNumUsesLimit`` is 0 (unlimited) because the sync identity
        is used by every host on every activation; a use limit would turn a
        busy deploy day into an outage.
        """
        _, payload = self._request(
            "POST",
            f"/api/v1/auth/universal-auth/identities/{identity_id}",
            json={
                "accessTokenTTL": token_ttl,
                "accessTokenMaxTTL": token_ttl,
                "accessTokenNumUsesLimit": 0,
                "accessTokenTrustedIps": _OPEN_TRUSTED_IPS,
                "clientSecretTrustedIps": _OPEN_TRUSTED_IPS,
            },
            description="attach universal auth",
        )
        client_id = payload.get("identityUniversalAuth", {}).get("clientId")
        if not client_id:
            raise InfisicalError("attach universal auth returned no clientId")
        return client_id

    def create_client_secret(
        self,
        identity_id: str,
        *,
        description: str = "nixfisical sync identity",
    ) -> str:
        """Mint a non-expiring, unlimited-use client secret for an identity.

        ``ttl`` and ``numUsesLimit`` are both 0 (unlimited) for the same reason
        as above: this credential is the estate's bootstrap-of-last-resort and
        rotating it is a deliberate operator action, not a timer.
        """
        _, payload = self._request(
            "POST",
            f"/api/v1/auth/universal-auth/identities/{identity_id}/client-secrets",
            json={"description": description, "numUsesLimit": 0, "ttl": 0},
            description="mint client secret",
        )
        client_secret = payload.get("clientSecret")
        if not client_secret:
            raise InfisicalError("mint client secret returned no clientSecret")
        return client_secret

    def universal_auth_login(self, credentials: UniversalAuthCredentials) -> str:
        """Exchange a client id/secret for an access token; also sets ``self.token``.

        Doubles as the bootstrap-completeness probe: if this succeeds against
        the credentials in the admin file, the instance is genuinely set up.
        """
        _, payload = self._request(
            "POST",
            "/api/v1/auth/universal-auth/login",
            json={
                "clientId": credentials.client_id,
                "clientSecret": credentials.client_secret,
            },
            authenticated=False,
            description="universal auth login",
        )
        token = payload.get("accessToken")
        if not token:
            raise InfisicalError("universal auth login returned no accessToken")
        self.token = token
        return token

    # -- projects, environments, folders ----------------------------------

    def list_projects(self, organization_id: str) -> dict[str, str]:
        """Return a ``{project name: project id}`` map for the organization.

        Infisical calls these "workspaces" at the v2 endpoint and "projects"
        everywhere else; we speak "project" outward and translate here.
        """
        _, payload = self._request(
            "GET",
            f"/api/v2/organizations/{organization_id}/workspaces",
            description="list projects",
        )
        workspaces = payload.get("workspaces") or []
        return {
            workspace["name"]: workspace["id"]
            for workspace in workspaces
            if workspace.get("name") and workspace.get("id")
        }

    def create_project(
        self,
        name: str,
        *,
        description: str | None = None,
        create_default_envs: bool = False,
    ) -> str:
        """Create a secret-manager project; return its id.

        ``create_default_envs`` is off: Infisical would otherwise seed every
        new project with Development/Staging/Production, and the declaration
        is what says which environments exist -- ``reconcile`` creates the
        declared ones a step later. A project seeded with three environments
        nobody declared is three things the operator has to delete by hand,
        and (until ``--prune-environments``) nothing here would.
        """
        body: dict[str, Any] = {
            "projectName": name,
            "type": "secret-manager",
            "shouldCreateDefaultEnvs": create_default_envs,
        }
        if description:
            body["projectDescription"] = description
        _, payload = self._request(
            "POST",
            "/api/v2/workspace",
            json=body,
            description=f"create project {name!r}",
        )
        project_id = payload.get("project", {}).get("id")
        if not project_id:
            raise InfisicalError(f"create project {name!r} returned no project id")
        return project_id

    def get_project(self, project_id: str) -> dict[str, Any]:
        """The project as the API describes it: name, description, environments.

        ``environments`` is a list of ``{id, name, slug}``; the id is what the
        delete endpoint wants, the slug is what the manifest declares.
        """
        _, payload = self._request(
            "GET",
            f"/api/v1/workspace/{project_id}",
            description="get project",
        )
        project = payload.get("workspace")
        return project if isinstance(project, dict) else payload

    def update_project(self, project_id: str, *, description: str) -> None:
        """``PATCH`` the project's description (the API caps it at 1024 chars)."""
        self._request(
            "PATCH",
            f"/api/v1/workspace/{project_id}",
            json={"description": description},
            description="update project description",
        )

    def delete_environment(self, project_id: str, environment_id: str) -> None:
        """Delete an environment by id. Everything in it goes with it.

        The caller is expected to have established that it is empty;
        ``reconcile`` does, and refuses otherwise.
        """
        self._request(
            "DELETE",
            f"/api/v1/workspace/{project_id}/environments/{environment_id}",
            description=f"delete environment {environment_id}",
        )

    def create_environment(self, project_id: str, *, name: str, slug: str) -> bool:
        """Ensure an environment exists. Returns True if we created it.

        400/409/422 are all tolerated: the version of Infisical decides which
        one it uses for "already exists", and none of them are distinguishable
        from the others without parsing prose error messages.
        """
        status, _ = self._request(
            "POST",
            f"/api/v1/workspace/{project_id}/environments",
            json={"name": name, "slug": slug},
            allow_status={400, 409, 422},
            description=f"create environment {slug!r}",
        )
        return 200 <= status < 300

    def create_folder(
        self, *, project_id: str, environment: str, path: str, name: str
    ) -> bool:
        """Ensure one folder exists under ``path``. Returns True if created.

        ``path`` is the *parent* directory and ``name`` is the leaf segment;
        the API has no mkdir -p, which is why reconcile.py expands ancestors.
        """
        status, _ = self._request(
            "POST",
            "/api/v1/folders",
            json={
                "workspaceId": project_id,
                "environment": environment,
                "path": path,
                "name": name,
            },
            allow_status={400, 409},
            description=f"create folder {path.rstrip('/')}/{name}",
        )
        return 200 <= status < 300

    # -- secrets -----------------------------------------------------------

    def create_secret(
        self,
        name: str,
        *,
        project_id: str,
        environment: str,
        secret_path: str,
        value: str,
    ) -> bool:
        """Attempt to create a secret. Returns False if it already existed.

        Conflicts (400/409/422) are tolerated so :meth:`upsert_secret` can fall
        through to a PATCH.
        """
        status, _ = self._request(
            "POST",
            f"/api/v3/secrets/raw/{name}",
            json={
                "workspaceId": project_id,
                "environment": environment,
                "secretPath": secret_path,
                "secretValue": value,
                "type": "shared",
            },
            allow_status={400, 409, 422},
            description=f"create secret {environment}:{secret_path}:{name}",
        )
        return 200 <= status < 300

    def update_secret(
        self,
        name: str,
        *,
        project_id: str,
        environment: str,
        secret_path: str,
        value: str,
    ) -> None:
        """Overwrite an existing secret's value."""
        self._request(
            "PATCH",
            f"/api/v3/secrets/raw/{name}",
            json={
                "workspaceId": project_id,
                "environment": environment,
                "secretPath": secret_path,
                "secretValue": value,
            },
            description=f"update secret {environment}:{secret_path}:{name}",
        )

    def upsert_secret(
        self,
        name: str,
        *,
        project_id: str,
        environment: str,
        secret_path: str,
        value: str,
    ) -> str:
        """Create-or-update a secret; return ``"created"`` or ``"updated"``.

        Infisical has no upsert endpoint, so this is POST-then-PATCH-on-conflict
        exactly as the Ansible role did it. The alternative -- list first, then
        branch -- costs an extra round trip per secret and still races.
        """
        created = self.create_secret(
            name,
            project_id=project_id,
            environment=environment,
            secret_path=secret_path,
            value=value,
        )
        if created:
            return "created"
        self.update_secret(
            name,
            project_id=project_id,
            environment=environment,
            secret_path=secret_path,
            value=value,
        )
        return "updated"

    def list_secrets(
        self, *, project_id: str, environment: str, path: str = "/"
    ) -> list[dict[str, Any]]:
        """List secrets recursively under ``path``.

        Returned dicts are the raw API objects; the reconciler reads only
        ``secretKey`` and ``secretPath`` from them. ``secretValue`` is present
        and must not be logged.
        """
        _, payload = self._request(
            "GET",
            "/api/v3/secrets/raw",
            params={
                "workspaceId": project_id,
                "environment": environment,
                "secretPath": path,
                "recursive": "true",
            },
            description=f"list secrets {environment}:{path}",
        )
        secrets = payload.get("secrets") or []
        return [secret for secret in secrets if isinstance(secret, dict)]

    def delete_secret(
        self, name: str, *, project_id: str, environment: str, secret_path: str
    ) -> None:
        """Delete a secret. Used only by prune."""
        self._request(
            "DELETE",
            f"/api/v3/secrets/raw/{name}",
            json={
                "workspaceId": project_id,
                "environment": environment,
                "secretPath": secret_path,
            },
            description=f"delete secret {environment}:{secret_path}:{name}",
        )

    # -- groups ------------------------------------------------------------
    #
    # Only the three calls ``sync-access`` needs, all of them on the current
    # (non-deprecated) membership routes. Deliberately absent: group creation.
    # It exists at POST /api/v1/organization/groups and answers 400 "plan
    # restriction" on every unlicensed self-hosted instance, so exposing it
    # here would only produce a confusing error at a distance; see
    # ``access.Database.create_group`` for what is done instead.

    def list_organization_groups(self) -> dict[str, str]:
        """Return ``{group name: id}`` for the token's organization.

        Slugs are included as additional keys so a caller can look a group up
        by either. Listing is not plan-gated -- only mutation is.
        """
        _, payload = self._request(
            "GET",
            "/api/v1/organizations/memberships/groups",
            params={"limit": 100},
            description="list organization groups",
        )
        found: dict[str, str] = {}
        for membership in payload.get("groupMemberships") or []:
            if not isinstance(membership, dict):
                continue
            group = membership.get("group") or {}
            group_id = group.get("id") or membership.get("groupId")
            if not group_id:
                continue
            for key in (group.get("name"), group.get("slug")):
                if key:
                    found[key] = group_id
        return found

    def list_project_groups(self, project_id: str) -> dict[str, str]:
        """Return ``{group id: role}`` for the groups already on a project.

        The role reported is the first permanent one; a group with several
        roles is something a human configured and this tool does not touch.
        """
        _, payload = self._request(
            "GET",
            f"/api/v1/projects/{project_id}/memberships/groups",
            description="list project groups",
        )
        found: dict[str, str] = {}
        for membership in payload.get("groupMemberships") or []:
            if not isinstance(membership, dict):
                continue
            group_id = membership.get("groupId") or (membership.get("group") or {}).get("id")
            if not group_id:
                continue
            roles = [
                role.get("role")
                for role in membership.get("roles") or []
                if isinstance(role, dict) and role.get("role")
            ]
            found[group_id] = roles[0] if roles else "?"
        return found

    def list_project_users(self, project_id: str) -> dict[str, str]:
        """Return ``{lowercased email or username: role}`` for a project's users.

        Group-derived access does not appear here -- this is the direct
        membership table only, which is exactly the question the caller has:
        a user can hold a project through a group and still not be listed.
        Both the email and the username are used as keys because Infisical
        allows them to differ and the operator knows the email.
        """
        _, payload = self._request(
            "GET",
            f"/api/v1/workspace/{project_id}/memberships",
            description="list project users",
        )
        found: dict[str, str] = {}
        for membership in payload.get("memberships") or []:
            if not isinstance(membership, dict):
                continue
            user = membership.get("user") or {}
            roles = [
                role.get("role")
                for role in membership.get("roles") or []
                if isinstance(role, dict) and role.get("role")
            ]
            role = roles[0] if roles else "?"
            for key in (user.get("email"), user.get("username")):
                if key:
                    found[str(key).strip().lower()] = role
        return found

    def add_user_to_project(self, *, project_id: str, email: str, role: str) -> None:
        """Add an existing organization member to a project with ``role``.

        Despite upstream describing this route as "Invite members to project",
        it sends no invitation for someone who is already in the organization:
        it creates the project membership directly. It is not plan-gated -- it
        is the same surface the UI's "Add member" button uses.
        """
        self._request(
            "POST",
            f"/api/v2/workspace/{project_id}/memberships",
            json={"emails": [email], "roleSlugs": [role]},
            description=f"add user to project with role {role!r}",
        )

    def add_group_to_project(self, *, project_id: str, group_id: str, role: str) -> None:
        """Grant a group a role on a project.

        Not plan-gated: upstream checks the license when a group is created or
        edited, and when a *custom* role is assigned, but not for attaching an
        existing group to a project with a built-in role.
        """
        self._request(
            "POST",
            f"/api/v1/projects/{project_id}/memberships/groups/{group_id}",
            json={"roles": [{"role": role, "isTemporary": False}]},
            description=f"add group to project with role {role!r}",
        )

    def list_project_identities(self, project_id: str) -> dict[str, str]:
        """Return ``{identity id: role}`` for the machine identities on a project.

        The mirror of :meth:`list_project_users` for the other kind of
        principal. Keyed by id rather than name because identity names are not
        unique in Infisical -- a name lookup can only tell you that *an*
        identity is called that, which is not the question a membership check
        is asking.
        """
        _, payload = self._request(
            "GET",
            f"/api/v2/workspace/{project_id}/identity-memberships",
            description="list project identities",
        )
        found: dict[str, str] = {}
        for membership in payload.get("identityMemberships") or []:
            if not isinstance(membership, dict):
                continue
            identity = membership.get("identity") or {}
            identity_id = identity.get("id") or membership.get("identityId")
            if not identity_id:
                continue
            roles = [
                role.get("role")
                for role in membership.get("roles") or []
                if isinstance(role, dict) and role.get("role")
            ]
            found[str(identity_id)] = roles[0] if roles else "?"
        return found

    def add_identity_to_project(
        self, *, project_id: str, identity_id: str, role: str
    ) -> None:
        """Grant a machine identity a role on a project.

        This is what makes a least-privilege host identity possible. An
        identity created with the organization role ``admin`` -- which is what
        ``bootstrap`` mints for ``fleet-sync`` -- reaches every project in the
        organization without any membership at all, so a host identity is
        created with ``no-access`` instead and reaches exactly the projects it
        is added to here.
        """
        self._request(
            "POST",
            f"/api/v2/workspace/{project_id}/identity-memberships/{identity_id}",
            json={"role": role},
            description=f"add identity to project with role {role!r}",
        )

    # -- app connections and secret syncs ----------------------------------
    #
    # The outbound half: Infisical pushing secrets onward on its own schedule.
    # A sync always names a connection; connections are referenced by name
    # here and never created -- authorising one is a browser round-trip with
    # GitHub (or whichever provider), which no reconciler should own.

    def get_app_connection(self, app: str, name: str) -> dict[str, Any] | None:
        """Return the connection of kind ``app`` named ``name``, or ``None``.

        ``app`` is the provider slug in the URL (``github``, ``aws``, ...).
        404 is the documented answer for "no such name" and is returned as
        ``None`` so the caller can report a missing connection as one error
        among many rather than aborting the run.
        """
        status, payload = self._request(
            "GET",
            f"/api/v1/app-connections/{app}/connection-name/{name}",
            allow_status={404},
            description=f"look up {app} connection {name!r}",
        )
        if status == 404:
            return None
        connection = payload.get("appConnection")
        return connection if isinstance(connection, dict) else None

    def list_secret_syncs(self, project_id: str) -> list[dict[str, Any]]:
        """Every secret sync in a project, across all destinations."""
        _, payload = self._request(
            "GET",
            "/api/v1/secret-syncs",
            params={"projectId": project_id},
            description="list secret syncs",
        )
        syncs = payload.get("secretSyncs") or []
        return [sync for sync in syncs if isinstance(sync, dict)]

    def create_secret_sync(self, destination: str, body: Mapping[str, Any]) -> dict[str, Any]:
        """``POST /secret-syncs/{destination}``; returns the created sync."""
        _, payload = self._request(
            "POST",
            f"/api/v1/secret-syncs/{destination}",
            json=body,
            description=f"create {destination} sync {body.get('name')!r}",
        )
        sync = payload.get("secretSync")
        return sync if isinstance(sync, dict) else payload

    def update_secret_sync(
        self, destination: str, sync_id: str, body: Mapping[str, Any]
    ) -> dict[str, Any]:
        """``PATCH /secret-syncs/{destination}/{id}``; returns the updated sync."""
        _, payload = self._request(
            "PATCH",
            f"/api/v1/secret-syncs/{destination}/{sync_id}",
            json=body,
            description=f"update {destination} sync {body.get('name') or sync_id!r}",
        )
        sync = payload.get("secretSync")
        return sync if isinstance(sync, dict) else payload

    def delete_secret_sync(
        self, destination: str, sync_id: str, *, remove_secrets: bool = False
    ) -> None:
        """Delete a sync. ``remove_secrets`` also unwinds what it wrote downstream."""
        self._request(
            "DELETE",
            f"/api/v1/secret-syncs/{destination}/{sync_id}",
            params={"removeSecrets": "true" if remove_secrets else "false"},
            description=f"delete {destination} sync {sync_id}",
        )

    def trigger_secret_sync(self, destination: str, sync_id: str) -> None:
        """Run a sync now (``POST .../sync-secrets``)."""
        self._request(
            "POST",
            f"/api/v1/secret-syncs/{destination}/{sync_id}/sync-secrets",
            description=f"trigger {destination} sync {sync_id}",
        )
