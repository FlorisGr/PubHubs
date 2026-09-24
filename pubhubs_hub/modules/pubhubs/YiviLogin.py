import hashlib
import hmac
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field

import nacl.secret
import nacl.utils

from synapse.api.ratelimiting import Ratelimiter
from synapse.http.server import DirectServeJsonResource, respond_with_json
from synapse.module_api import ModuleApi
from synapse.module_api.errors import ConfigError
from synapse.util.async_helpers import Linearizer

try:
    import conf.modules.pseudonyms
except:
    pass # TODO

from ._base64url import b64url_decode, b64url_encode

logger = logging.getLogger("synapse.contrib." + __name__)

# Module that lets users log in to this hub directly with Yivi, for hubs that run without
# PubHubs Central (a 'standalone' hub):
#   - the '_synapse/client/.ph/yivi-login/' endpoints
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

    async def login(self, pseudonym: str) -> dict:
        async with self._linearizer.queue(pseudonym):
            mxid = await self._api._store.get_user_by_external_id(AUTH_PROVIDER, pseudonym)
            new_user = mxid is None

            if new_user:
                # Random, not derived from the pseudonym, as Core does, so the localpart can't be
                # traced back to the disclosed attribute even by someone holding the pseudonym key.
                longlocalpart = nacl.utils.random(32).hex()
                mxid = await conf.modules.pseudonyms.register_under_fresh_pseudonym(
                    longlocalpart,
                    lambda localpart: self._api.register_user(localpart, localpart, None, False),
                )
                await self._api.record_user_external_id(AUTH_PROVIDER, pseudonym, mxid)
                logger.info(f"registered {mxid} via yivi login")
            elif await self._api._store.get_user_deactivated_status(mxid):
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
        requestor_token = self._login.unseal_token(sealed)
        if requestor_token is None or not requestor_token_regex.fullmatch(requestor_token):
            respond_with_json(request, 400, { 'Err': 'BadRequest' }, send_cors=True)
            return

        result = await self._login._api.http_client.get_json(f"{self._login._config.yivi_url}/session/{requestor_token}/result")
        value = check_result(result, self._login._config.attribute)
        if value is None:
            logger.info(f"yivi login session did not yield a valid disclosure (status {result.get('status')}, proof {result.get('proofStatus')})")
            respond_with_json(request, 403, { 'Err': 'NotDisclosed' }, send_cors=True)
            return

        # Checked after the disclosure, so polling an unfinished session doesn't use it up.
        if not self._login.consume(requestor_token):
            respond_with_json(request, 400, { 'Err': 'BadRequest' }, send_cors=True)
            return

        answer = await self._login.login(self._login.pseudonym(value))
        respond_with_json(request, 200 if 'Ok' in answer else 403, answer, send_cors=True)
