import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
from dataclasses import dataclass, field
from urllib.parse import urlencode

import nacl.secret
import nacl.utils

from synapse.api.ratelimiting import Ratelimiter
from synapse.http.server import DirectServeHtmlResource, DirectServeJsonResource, respond_with_json
from synapse.module_api import ModuleApi
from synapse.module_api.errors import ConfigError
from synapse.util.async_helpers import Linearizer

try:
    import conf.modules.pseudonyms
except:
    pass # TODO

from ._base64url import b64url_decode, b64url_encode
from ._yivi_pages import language_of, origin_of, register_assets, render_page, respond_with_page, texts

logger = logging.getLogger("synapse.contrib." + __name__)

# Module that lets users log in to this hub directly with Yivi, for hubs that run without
# PubHubs Central (a 'standalone' hub):
#   - the '_synapse/client/.ph/yivi-login/' endpoints, used by the hub client
#   - a Matrix SSO identity provider, so other Matrix clients (e.g. Element) can log in too, on a
#     page the hub serves itself (see _yivi_pages.py)
#
# The user discloses one identifying attribute (by default their email address) to the Yivi
# server bundled with the hub.  The hub never stores that value: it keys the user on
# HMAC(pseudonym key, attribute), so the database alone reveals nothing, and two hubs (which have
# different keys) cannot link their users.  The Matrix localpart is random, like the one Core
# gives users entering through PubHubs Central.

# Name under which the pseudonyms are stored in synapse's user_external_ids table.
AUTH_PROVIDER = "yivi"

# How long a started login may take before its result is no longer accepted.  The Yivi server
# times sessions out after 5 minutes of inactivity by default; allow a little more.
LOGIN_TIMEOUT_SECONDS = 10 * 60

# Requestor tokens are alphanumeric (20 characters in practice, but don't depend on that).
requestor_token_regex = re.compile("[a-zA-Z0-9]+")

# The placeholder OIDC provider update_config.py configures for every hub (idp_id 'pubhubs', which
# synapse prefixes).  Nothing can log in with it; on a standalone hub it would only show up next to
# Yivi as a broken button in other Matrix clients.
PLACEHOLDER_IDP_ID = "oidc-pubhubs"

# Binds an SSO login to the browser that started it, so nobody can have someone else's browser
# finish a login they started (and log that browser in to their account).  SameSite=Lax is enough:
# the completing request is a top-level GET.
SSO_COOKIE = "yivi_sso_session"
SSO_COOKIE_PATH = "/_synapse/client/.ph/yivi-login/"

# The page SSO logins are run on, under the endpoints it talks to.
SSO_PAGE_PATH = "/_synapse/client/.ph/yivi-login/sso"


@dataclass
class Config:
    attribute: str = "pbdf.sidn-pbdf.email.email"
    pseudonym_key_path: str = "/data/yivi_login_pseudonym.key"
    yivi_url: str = "http://localhost:8089"
    public_yivi_url: str | None = None
    # Shown by the hub client; hubs entered through PubHubs Central get their name from its registry.
    hub_name: str | None = None
    linked_hubs: list = field(default_factory=list)


class YiviLogin:
    def __init__(self, config: Config, api: ModuleApi):
        self._config = config
        self._api = api
        self._public_yivi_url = config.public_yivi_url or api.public_baseurl
        self._pseudonym_key = load_or_create_key(config.pseudonym_key_path)

        # Seals the requestor token we hand to the client, so the client cannot fetch session
        # results on its own, and the token expires.  Ephemeral: a restart only aborts logins in
        # progress.
        self._secret_box = nacl.secret.Aead(nacl.utils.random(nacl.secret.Aead.KEY_SIZE))
        # Requestor tokens whose result was already used to log in, with the time they were used.
        self._consumed = {}
        # Serializes logins per pseudonym, so two simultaneous first logins create one user.
        self._linearizer = Linearizer(name="yivi_login", clock=api._hs.get_clock())
        # The start endpoint creates Yivi sessions without authentication, so limit it per IP like
        # synapse limits its own /login.
        self._ratelimiter = Ratelimiter(
            store=api._store,
            clock=api._hs.get_clock(),
            cfg=api._hs.config.ratelimiting.rc_login_address,
        )

        info = { 'Ok': {
            'hub_name': config.hub_name or api.server_name,
            'attribute': config.attribute,
            'linked_hubs': config.linked_hubs,
        }}

        api.register_web_resource('/_synapse/client/.ph/yivi-login/info', InfoEP(info))
        api.register_web_resource('/_synapse/client/.ph/yivi-login/start', StartEP(self))
        api.register_web_resource('/_synapse/client/.ph/yivi-login/result', ResultEP(self))
        api.register_web_resource('/_synapse/client/.ph/yivi-login/sso-complete', SsoCompleteEP(self))
        api.register_web_resource(SSO_PAGE_PATH, SsoPageEP(self))
        # also used by the secured room pages, see _secured_room_knock.py
        register_assets(api)

        # Synapse only advertises m.login.sso when an OIDC, SAML or CAS provider is configured, so
        # this relies on the placeholder OIDC provider update_config.py always adds.  That one was
        # registered before any module loaded, so it can be dropped here.
        sso_handler = api._hs.get_sso_handler()
        sso_handler._identity_providers.pop(PLACEHOLDER_IDP_ID, None)
        sso_handler.register_identity_provider(YiviIdentityProvider(
            self,
            # On public_baseurl: synapse redirects /login/sso/redirect there first, so that is where
            # the cookie is set.
            page_url=api.public_baseurl.rstrip('/') + SSO_PAGE_PATH,
            secure_cookie=api.public_baseurl.startswith('https://'),
        ))

    @staticmethod
    def parse_config(config):
        config = config or {}
        parsed = Config(
            attribute=config.get('attribute', Config.attribute),
            pseudonym_key_path=config.get('pseudonym_key_path', Config.pseudonym_key_path),
            yivi_url=config.get('yivi_url', Config.yivi_url),
            public_yivi_url=config.get('public_yivi_url'),
            hub_name=config.get('hub_name'),
            linked_hubs=config.get('linked_hubs', []),
        )

        if not isinstance(parsed.attribute, str) or parsed.attribute.count('.') != 3:
            raise ConfigError("yivi login: 'attribute' should be a full Yivi attribute id, like pbdf.sidn-pbdf.email.email")

        if not isinstance(parsed.linked_hubs, list):
            raise ConfigError("yivi login: 'linked_hubs' should be a list")
        for hub in parsed.linked_hubs:
            if not isinstance(hub, dict) or not isinstance(hub.get('name'), str) or not isinstance(hub.get('url'), str):
                raise ConfigError(f"yivi login: every linked hub needs a 'name' and a 'url', got {hub}")
            # the client renders these as links, so refuse e.g. javascript: urls
            if not hub['url'].startswith('https://') and not hub['url'].startswith('http://'):
                raise ConfigError(f"yivi login: linked hub url should be http(s), got {hub['url']}")

        return parsed

    def pseudonym(self, value: str) -> str:
        """The stable, hub-specific pseudonym for the disclosed attribute value."""
        # The attribute id is mixed in, so switching to another attribute cannot collide with
        # existing users.
        message = f"{self._config.attribute}\n{normalize(self._config.attribute, value)}"
        return hmac.new(self._pseudonym_key, message.encode('utf-8'), hashlib.sha256).hexdigest()

    def seal_token(self, requestor_token: str) -> str:
        return b64url_encode(self._secret_box.encrypt(json.dumps({
            'token': requestor_token,
            'iat': time.time(),
        }).encode('ascii'), b"yivi-login"))

    def unseal_token(self, sealed: str) -> str | None:
        """The requestor token in `sealed`, or None when it's invalid or expired."""
        try:
            state = json.loads(self._secret_box.decrypt(b64url_decode(sealed), b"yivi-login"))
        except Exception:
            return None
        if time.time() - state['iat'] > LOGIN_TIMEOUT_SECONDS:
            return None
        return state['token']

    def consume(self, requestor_token: str) -> bool:
        """Mark a session result as used; False when it was used before."""
        now = time.time()
        # a consumed token can only come back while its seal is valid, so forget it after that
        self._consumed = {t: at for t, at in self._consumed.items() if now - at <= LOGIN_TIMEOUT_SECONDS}
        if requestor_token in self._consumed:
            return False
        self._consumed[requestor_token] = now
        return True

    async def find_or_register(self, pseudonym: str) -> tuple[str, bool]:
        """The user with `pseudonym`, registered first when there is none yet.

        Returns:
            the user's mxid, and whether they were registered just now
        """
        async with self._linearizer.queue(pseudonym):
            mxid = await self._api._store.get_user_by_external_id(AUTH_PROVIDER, pseudonym)
            if mxid is not None:
                return mxid, False

            # Random, not derived from the pseudonym, as Core does, so the localpart can't be
            # traced back to the disclosed attribute even by someone holding the pseudonym key.
            longlocalpart = nacl.utils.random(32).hex()
            mxid = await conf.modules.pseudonyms.register_under_fresh_pseudonym(
                longlocalpart,
                lambda localpart: self._api.register_user(localpart, localpart, None, False),
            )
            await self._api.record_user_external_id(AUTH_PROVIDER, pseudonym, mxid)
            logger.info(f"registered {mxid} via yivi login")
            return mxid, True

    async def login(self, pseudonym: str) -> dict:
        mxid, new_user = await self.find_or_register(pseudonym)
        if not new_user and await self._api._store.get_user_deactivated_status(mxid):
            # otherwise deactivating would not keep anyone out: they'd just log in again
            logger.info(f"refused yivi login of deactivated user {mxid}")
            return { 'Err': 'Deactivated' }

        (device_id, access_token, _, _) = await self._api.register_device(mxid)

        return { 'Ok': {
            'access_token': access_token,
            'device_id': device_id,
            'new_user': new_user,
            'mxid': mxid,
        }}

    async def redeem(self, sealed: str) -> tuple[str | None, str | None]:
        """Use up the Yivi session behind the sealed requestor token.

        Returns:
            the pseudonym of whoever disclosed the attribute, or None and an error code
        """
        requestor_token = self.unseal_token(sealed)
        if requestor_token is None or not requestor_token_regex.fullmatch(requestor_token):
            return (None, 'BadRequest')

        result = await self._api.http_client.get_json(f"{self._config.yivi_url}/session/{requestor_token}/result")
        value = check_result(result, self._config.attribute)
        if value is None:
            logger.info(f"yivi login session did not yield a valid disclosure (status {result.get('status')}, proof {result.get('proofStatus')})")
            return (None, 'NotDisclosed')

        # Checked after the disclosure, so polling an unfinished session doesn't use it up.
        if not self.consume(requestor_token):
            return (None, 'BadRequest')

        return (self.pseudonym(value), None)

    def seal_sso_state(self, nonce: str, client_redirect_url: str | None, ui_auth_session_id: str | None) -> str:
        """What the hub client passes back to finish an SSO login: where it came from, sealed so
        the client cannot change it."""
        return b64url_encode(self._secret_box.encrypt(json.dumps({
            'nonce': nonce,
            'redirect': client_redirect_url,
            'uia': ui_auth_session_id,
            'iat': time.time(),
        }).encode('utf-8'), b"yivi-login-sso"))

    def unseal_sso_state(self, sealed: str) -> dict | None:
        """The state in `sealed`, or None when it's invalid or expired."""
        try:
            state = json.loads(self._secret_box.decrypt(b64url_decode(sealed), b"yivi-login-sso"))
        except Exception:
            return None
        if time.time() - state['iat'] > LOGIN_TIMEOUT_SECONDS:
            return None
        return state


class YiviIdentityProvider:
    """Offers the Yivi login to Matrix clients as SSO (m.login.sso), see synapse's
    SsoIdentityProvider.

    Synapse redirects the browser here from /login/sso/redirect.  We send it on to SsoPageEP,
    which runs the Yivi session, and then navigates to SsoCompleteEP.  That checks the disclosure
    and hands the user back to synapse, which gives the Matrix client a login token (after asking
    the user to confirm, for clients not in sso.client_whitelist).
    """

    idp_id = AUTH_PROVIDER
    idp_name = "Yivi"
    idp_icon = None
    idp_brand = None

    def __init__(self, login: YiviLogin, page_url: str, secure_cookie: bool):
        self._login = login
        self._page_url = page_url
        self._secure_cookie = secure_cookie

    async def handle_redirect_request(self, request, client_redirect_url: bytes | None, ui_auth_session_id: str | None = None) -> str:
        nonce = secrets.token_urlsafe(16)
        options = f"Path={SSO_COOKIE_PATH}; Max-Age={LOGIN_TIMEOUT_SECONDS}; HttpOnly; SameSite=Lax"
        if self._secure_cookie:
            options += "; Secure"
        request.responseHeaders.addRawHeader(b"Set-Cookie", f"{SSO_COOKIE}={nonce}; {options}".encode('ascii'))

        redirect = client_redirect_url.decode('utf-8') if client_redirect_url is not None else None
        state = self._login.seal_sso_state(nonce, redirect, ui_auth_session_id)
        return f"{self._page_url}?{urlencode({'state': state})}"


def normalize(attribute: str, value: str) -> str:
    """Make equivalent attribute values give the same pseudonym."""
    value = value.strip()
    # Email addresses are case-insensitive in practice, and Yivi issues them as the user typed them.
    if attribute.endswith('.email'):
        value = value.lower()
    return value


def load_or_create_key(path: str) -> bytes:
    """Read the pseudonym key, generating it on first boot.  Losing it loses every account's link to
    its user, so it lives with the rest of the persistent hub data."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        with open(path, 'rb') as f:
            key = f.read()
        if len(key) != 32:
            raise ConfigError(f"yivi login: pseudonym key at {path} should be 32 bytes, found {len(key)}")
        return key

    key = nacl.utils.random(32)
    with os.fdopen(fd, 'wb') as f:
        f.write(key)
    logger.warning(f"yivi login: generated a new pseudonym key at {path}; back it up, users cannot log in to their accounts without it")
    return key


def check_result(result: dict, attribute: str) -> str | None:
    """The disclosed value of `attribute` when `result` is a finished, valid disclosure of it."""
    if result.get('status') != 'DONE' or result.get('proofStatus') != 'VALID':
        return None
    disclosed = [a for con in (result.get('disclosed') or []) for a in con]
    values = [a.get('rawvalue') for a in disclosed if a.get('id') == attribute and a.get('status') == 'PRESENT']
    if len(values) != 1 or not isinstance(values[0], str) or not values[0].strip():
        return None
    return values[0]


class InfoEP(DirectServeJsonResource):
    def __init__(self, contents):
        super().__init__()
        self._contents = contents

    async def _async_render_GET(self, request):
        respond_with_json(request, 200, self._contents, send_cors=True)


class StartEP(DirectServeJsonResource):
    def __init__(self, login: YiviLogin):
        super().__init__()
        self._login = login

    async def _async_render_POST(self, request):
        await self._login._ratelimiter.ratelimit(None, key=(request.get_client_ip_if_available(),))

        session_request = {
            "@context": "https://irma.app/ld/request/disclosure/v2",
            "disclose": [[[self._login._config.attribute]]],
        }
        answer = await self._login._api.http_client.post_json_get_json(f"{self._login._config.yivi_url}/session", session_request)

        # The Yivi app and frontend reach the Yivi server through HubClientApi's proxy.
        session_ptr = answer["sessionPtr"]
        session_ptr["u"] = self._login._public_yivi_url.rstrip('/') + "/_synapse/client/yiviproxy/irma/" + session_ptr["u"]

        respond_with_json(request, 200, {
            'sessionPtr': session_ptr,
            'frontendRequest': answer.get('frontendRequest'),
            'token': self._login.seal_token(answer['token']),
        }, send_cors=True)


class ResultEP(DirectServeJsonResource):
    def __init__(self, login: YiviLogin):
        super().__init__()
        self._login = login

    async def _async_render_POST(self, request):
        sealed = request.args.get(b"session_token", [b""])[0].decode('ascii', errors='replace')
        (pseudonym, error) = await self._login.redeem(sealed)
        if pseudonym is None:
            respond_with_json(request, 403 if error == 'NotDisclosed' else 400, { 'Err': error }, send_cors=True)
            return

        answer = await self._login.login(pseudonym)
        respond_with_json(request, 200 if 'Ok' in answer else 403, answer, send_cors=True)


class SsoPageEP(DirectServeHtmlResource):
    """The page an SSO login runs its Yivi session on."""

    def __init__(self, login: YiviLogin):
        super().__init__()
        self._login = login

    async def _async_render_GET(self, request):
        sealed = request.args.get(b"state", [b""])[0].decode('ascii', errors='replace')
        if self._login.unseal_sso_state(sealed) is None:
            self._login._api._hs.get_sso_handler().render_error(request, "invalid_session", "This login has expired. Please start again from your Matrix app.", 400)
            return

        language = language_of(request)
        t = texts(language)
        respond_with_page(request, render_page(
            language=language,
            title=t["sso_title"],
            heading=self._login._config.hub_name or self._login._api.server_name,
            explanation=t["sso_explanation"],
            config={
                'page': 'sso',
                'language': language,
                'state': sealed,
                'texts': {k: t[k] for k in ("failed", "retry")},
            },
            yivi_origin=origin_of(self._login._public_yivi_url),
        ))


class SsoCompleteEP(DirectServeHtmlResource):
    """Where the hub client sends the browser once the Yivi session of an SSO login is done.

    A GET, since it is a top-level navigation, which is also what the SameSite=Lax cookie needs.
    """

    def __init__(self, login: YiviLogin):
        super().__init__()
        self._login = login

    async def _async_render_GET(self, request):
        sso_handler = self._login._api._hs.get_sso_handler()

        def arg(name: bytes) -> str:
            return request.args.get(name, [b""])[0].decode('ascii', errors='replace')

        state = self._login.unseal_sso_state(arg(b"state"))
        nonce = request.getCookie(SSO_COOKIE.encode('ascii'))
        if state is None or nonce is None or not hmac.compare_digest(nonce.decode('ascii', errors='replace'), state['nonce']):
            sso_handler.render_error(request, "invalid_session", "This login has expired or was started in another browser. Please start again from your Matrix app.", 400)
            return

        (pseudonym, _) = await self._login.redeem(arg(b"session_token"))
        if pseudonym is None:
            sso_handler.render_error(request, "not_disclosed", "The Yivi session did not complete, or was already used. Please start again from your Matrix app.", 403)
            return

        # used up, so it can't finish a second login
        request.addCookie(SSO_COOKIE, "", path=SSO_COOKIE_PATH, max_age="0")

        if state['uia'] is not None:
            # Re-authenticating an existing session (e.g. to remove a device): synapse checks the
            # pseudonym belongs to that session's user, and never registers anyone here.
            await sso_handler.complete_sso_ui_auth_request(AUTH_PROVIDER, pseudonym, state['uia'], request)
            return

        (mxid, new_user) = await self._login.find_or_register(pseudonym)
        # Refuses deactivated users itself, with an explanatory page.
        await self._login._api.complete_sso_login_async(mxid, request, state['redirect'], new_user=new_user, auth_provider_id=AUTH_PROVIDER)
