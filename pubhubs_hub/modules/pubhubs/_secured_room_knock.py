import hashlib
import hmac
import html
import json
import logging
import re
import time
from typing import Optional
from urllib.parse import urlencode

import nacl.secret
import nacl.utils

from synapse.api.constants import EventTypes, JoinRules, Membership
from synapse.api.ratelimiting import Ratelimiter
from synapse.http.server import DirectServeHtmlResource, DirectServeJsonResource, respond_with_json
from synapse.module_api import ModuleApi

from ._base64url import b64url_decode, b64url_encode
from ._hub_client_api_config import HubClientApiConfig
from ._secured_rooms_class import SecuredRoom
from ._store import HubStore
from ._yivi_pages import language_of, origin_of, render_page, respond_with_page, texts

logger = logging.getLogger("synapse.contrib." + __name__)

# Lets users of other Matrix clients (e.g. Element) into secured rooms, on standalone hubs (see
# YiviLogin.py).  Those clients cannot run a Yivi session, so there a secured room's join rule is
# 'knock':
#   - the user knocks ('Ask to join');
#   - the hub sends them a server notice with a link to a page it serves itself (see
#     _yivi_pages.py), which runs the room's Yivi disclosure against the
#     '_synapse/client/.ph/secured-room-link/' endpoints;
#   - when the disclosure fits the room, the hub invites the user and joins them.
# Users that were let in before (and hub admins) are invited straight away, without a link.  The
# hub client's own flow keeps working because granting access also invites (see grant_access).

# How long a link in a notice can be used.  A user who is still knocking cannot knock again to get
# a new one, so this is generous; withdrawing the knock and knocking again does give a new link.
LINK_LIFETIME_SECONDS = 7 * 24 * 60 * 60

# How long a started disclosure may take before its result is no longer accepted.
SESSION_TIMEOUT_SECONDS = 10 * 60

# The page a link opens, under the endpoints it talks to.
LINK_PAGE_PATH = "/_synapse/client/.ph/secured-room-link/page"

# Requestor tokens are alphanumeric (20 characters in practice, but don't depend on that).
requestor_token_regex = re.compile("[a-zA-Z0-9]+")


def joined_with_attributes_notice(user_id: str, disclosed: dict) -> str:
    # The hub client parses this text to show attributes on profiles, so keep it exactly like this.
    return f"{user_id} joined the room with attributes {disclosed}"


async def grant_access(module_api: ModuleApi, config: HubClientApiConfig, store: HubStore, user_id: str, room_id: str, disclosed: dict) -> None:
    """Let a user into a secured room after they disclosed what it asks for."""
    await store.allow(user_id, room_id, time.time())

    await module_api.create_and_send_event_into_room(
        {
            "type": "m.room.message",
            "room_id": room_id,
            "sender": config.server_notices_user,
            "content": {
                "body": joined_with_attributes_notice(user_id, disclosed),
                "msgtype": "m.notice",
            },
        }
    )

    await invite_to_knock_room(module_api, config, user_id, room_id)


async def invite_to_knock_room(module_api: ModuleApi, config: HubClientApiConfig, user_id: str, room_id: str) -> None:
    """Invite the user when the room's join rule is 'knock', since joining one takes an invite.
    Does nothing for other rooms, which the user can simply join."""
    state = await module_api.get_room_state(room_id, [(EventTypes.JoinRules, ""), (EventTypes.Member, user_id)])
    join_rules = state.get((EventTypes.JoinRules, ""))
    if join_rules is None or join_rules.content.get("join_rule") != JoinRules.KNOCK:
        return
    member = state.get((EventTypes.Member, user_id))
    if member is not None and member.content.get("membership") in (Membership.JOIN, Membership.INVITE):
        return
    try:
        await module_api.update_room_membership(config.server_notices_user, user_id, room_id, Membership.INVITE)
    except Exception as e:
        # e.g. a banned user: access was granted, but moderation still has the last word
        logger.warning(f"could not invite {user_id} to secured room {room_id}: {e}")


def allowed_disclosure(result: dict, room: SecuredRoom) -> Optional[dict]:
    """The attributes to show when the Yivi `result` fits the entry requirements of `room`, with
    an empty value for those not shown in profiles; None when it doesn't fit."""
    if result.get("proofStatus") != "VALID" or result.get("disclosed") is None:
        return None

    disclosed_attributes = {a.get("id"): a.get("rawvalue") for con in result["disclosed"] for a in con}
    if len(disclosed_attributes) < 1:
        return None

    disclosed_to_show = {}
    for required, room_attribute in room.accepted.items():
        disclosed_value = disclosed_attributes.get(required)
        if not disclosed_value or not room_attribute:
            return None
        if len(room_attribute.accepted_values) != 0 and disclosed_value not in room_attribute.accepted_values:
            return None
        disclosed_to_show[required] = disclosed_value if room_attribute.profile else ""
    return disclosed_to_show


def link_key(module_api: ModuleApi) -> bytes:
    """Seals links, so that they survive restarts: derived from synapse's macaroon secret, which
    PubHubs already requires hub owners to set and keep."""
    return hmac.new(module_api._hs.config.key.macaroon_secret_key, b"pubhubs secured room links", hashlib.sha256).digest()


class SecuredRoomKnocks:
    def __init__(self, module_api: ModuleApi, config: HubClientApiConfig, store: HubStore, link_secret: bytes):
        self._module_api = module_api
        self._config = config
        self._store = store
        self._link_box = nacl.secret.Aead(link_secret)
        # Seals the requestor tokens handed to the hub client.  Ephemeral: a restart only aborts
        # disclosures in progress.
        self._session_box = nacl.secret.Aead(nacl.utils.random(nacl.secret.Aead.KEY_SIZE))
        # Requestor tokens whose result was already used, with the time they were used.
        self._consumed = {}

    def register(self) -> None:
        self._module_api.register_third_party_rules_callbacks(on_new_event=self.on_new_event)
        self._module_api.register_web_resource(LINK_PAGE_PATH, LinkPageEP(self))
        self._module_api.register_web_resource('/_synapse/client/.ph/secured-room-link/start', LinkStartEP(self))
        self._module_api.register_web_resource('/_synapse/client/.ph/secured-room-link/result', LinkResultEP(self))

    # -- links ---------------------------------------------------------------------------------

    def seal_link(self, user_id: str, room_id: str) -> str:
        return b64url_encode(self._link_box.encrypt(json.dumps({
            'user': user_id,
            'room': room_id,
            'iat': time.time(),
        }).encode('utf-8'), b"secured-room-link"))

    def unseal_link(self, sealed: str) -> Optional[tuple[str, str]]:
        """The user and room of the link, or None when it's invalid or expired."""
        try:
            link = json.loads(self._link_box.decrypt(b64url_decode(sealed), b"secured-room-link"))
        except Exception:
            return None
        if time.time() - link['iat'] > LINK_LIFETIME_SECONDS:
            return None
        return (link['user'], link['room'])

    def link_url(self, user_id: str, room_id: str) -> str:
        return f"{self._module_api.public_baseurl.rstrip('/')}{LINK_PAGE_PATH}?{urlencode({'link': self.seal_link(user_id, room_id)})}"

    # -- disclosure sessions -------------------------------------------------------------------

    def seal_session(self, requestor_token: str, user_id: str, room_id: str) -> str:
        return b64url_encode(self._session_box.encrypt(json.dumps({
            'token': requestor_token,
            'user': user_id,
            'room': room_id,
            'iat': time.time(),
        }).encode('utf-8'), b"secured-room-session"))

    def unseal_session(self, sealed: str, user_id: str, room_id: str) -> Optional[str]:
        """The requestor token in `sealed`, when it is valid and was started for this user and room."""
        try:
            session = json.loads(self._session_box.decrypt(b64url_decode(sealed), b"secured-room-session"))
        except Exception:
            return None
        if time.time() - session['iat'] > SESSION_TIMEOUT_SECONDS:
            return None
        if session['user'] != user_id or session['room'] != room_id:
            return None
        if not requestor_token_regex.fullmatch(session['token']):
            return None
        return session['token']

    def consume(self, requestor_token: str) -> bool:
        """Mark a session result as used; False when it was used before."""
        now = time.time()
        # a consumed token can only come back while its seal is valid, so forget it after that
        self._consumed = {t: at for t, at in self._consumed.items() if now - at <= SESSION_TIMEOUT_SECONDS}
        if requestor_token in self._consumed:
            return False
        self._consumed[requestor_token] = now
        return True

    # -- knocks --------------------------------------------------------------------------------

    async def on_new_event(self, event, _state_events) -> None:
        if event.type != EventTypes.Member or event.content.get("membership") != Membership.KNOCK:
            return
        user_id = event.state_key
        if event.sender != user_id or not self._module_api.is_mine(user_id):
            return
        room = await self._store.get_secured_room(event.room_id)
        if room is None:
            return

        # Let in whoever a plain join would have let in before the join rule was 'knock'.  The
        # hub client knocks when a join is refused (e.g. rejoining after a kick), and retries.
        if await self._store.is_allowed(user_id, room.room_id) or await self._module_api.is_user_admin(user_id):
            await invite_to_knock_room(self._module_api, self._config, user_id, room.room_id)
            return

        await self.send_link(user_id, room)

    async def send_link(self, user_id: str, room: SecuredRoom) -> None:
        url = self.link_url(user_id, room.room_id)
        content = {
            "msgtype": "m.text",
            "body": f"The room \"{room.name}\" is only open to people who show some of their attributes with Yivi. To join it, open this link: {url}",
            "format": "org.matrix.custom.html",
            "formatted_body": (
                f"The room <b>{html.escape(room.name)}</b> is only open to people who show some of their attributes with Yivi. "
                f"<a href=\"{html.escape(url)}\">Show them with Yivi to join</a>"
            ),
        }
        await self._module_api._hs.get_server_notices_manager().send_notice(user_id, content)
        logger.info(f"sent {user_id} a link to join secured room {room.room_id}")

    # -- the link page -------------------------------------------------------------------------

    async def room_of_link(self, sealed: str) -> Optional[tuple[str, SecuredRoom]]:
        unsealed = self.unseal_link(sealed)
        if unsealed is None:
            return None
        (user_id, room_id) = unsealed
        room = await self._store.get_secured_room(room_id)
        if room is None:
            return None
        return (user_id, room)

    async def complete(self, user_id: str, room: SecuredRoom, sealed_session: str) -> dict:
        requestor_token = self.unseal_session(sealed_session, user_id, room.room_id)
        if requestor_token is None:
            return {'Err': 'BadRequest'}

        result = await self._module_api.http_client.get_json(f"{self._config.yivi_url_web}/session/{requestor_token}/result")
        disclosed = allowed_disclosure(result, room)
        if disclosed is None:
            logger.info(f"disclosure for secured room {room.room_id} did not fit (status {result.get('status')}, proof {result.get('proofStatus')})")
            return {'Err': 'NotAllowed'}

        # Checked after the disclosure, so polling an unfinished session doesn't use it up.
        if not self.consume(requestor_token):
            return {'Err': 'BadRequest'}

        await grant_access(self._module_api, self._config, self._store, user_id, room.room_id, disclosed)
        # They knocked to get here, so they want to be in: don't leave them an invite to accept.
        try:
            await self._module_api.update_room_membership(user_id, user_id, room.room_id, Membership.JOIN)
        except Exception as e:
            logger.warning(f"could not join {user_id} to secured room {room.room_id}, leaving the invite: {e}")

        return {'Ok': {'room_id': room.room_id, 'room_name': room.name}}


def link_arg(request, name: bytes) -> str:
    return request.args.get(name, [b""])[0].decode('ascii', errors='replace')


class LinkPageEP(DirectServeHtmlResource):
    """The page a link in a notice opens: runs the room's Yivi disclosure."""

    def __init__(self, knocks: SecuredRoomKnocks):
        super().__init__()
        self._knocks = knocks

    async def _async_render_GET(self, request):
        language = language_of(request)
        t = texts(language)
        heading = self._knocks._config.hub_name
        link = link_arg(request, b"link")

        found = await self._knocks.room_of_link(link)
        if found is None:
            respond_with_page(request, render_page(language=language, title=t["room_title"], heading=heading, explanation=t["invalid_link"]), 400)
            return
        (_, room) = found

        respond_with_page(request, render_page(
            language=language,
            title=t["room_title"],
            heading=heading,
            explanation=t["room_explanation"].format(room=room.name),
            config={
                'page': 'room',
                'language': language,
                'link': link,
                'texts': {
                    "failed": t["failed"],
                    "not_allowed": t["not_allowed"],
                    "retry": t["retry"],
                    "joined": t["joined"].format(room=room.name),
                    "open_room": t["open_room"],
                },
            },
            yivi_origin=origin_of(self._knocks._config.public_yivi_url),
        ))


class LinkStartEP(DirectServeJsonResource):
    def __init__(self, knocks: SecuredRoomKnocks):
        super().__init__()
        self._knocks = knocks
        api = knocks._module_api
        # Starts Yivi sessions for anyone holding a link, so limit it per IP like synapse limits /login.
        self._ratelimiter = Ratelimiter(
            store=api._store,
            clock=api._hs.get_clock(),
            cfg=api._hs.config.ratelimiting.rc_login_address,
        )

    async def _async_render_POST(self, request):
        await self._ratelimiter.ratelimit(None, key=(request.get_client_ip_if_available(),))

        found = await self._knocks.room_of_link(link_arg(request, b"link"))
        if found is None:
            respond_with_json(request, 400, {'Err': 'InvalidLink'})
            return
        (user_id, room) = found

        config = self._knocks._config
        session_request = {
            "@context": "https://irma.app/ld/request/disclosure/v2",
            "disclose": [[[attribute]] for attribute in room.accepted.keys()],
        }
        answer = await self._knocks._module_api.http_client.post_json_get_json(f"{config.yivi_url_web}/session", session_request)

        # The Yivi app and frontend reach the Yivi server through the module's proxy.
        session_ptr = answer["sessionPtr"]
        session_ptr["u"] = config.public_yivi_url + "_synapse/client/yiviproxy/irma/" + session_ptr["u"]

        respond_with_json(request, 200, {
            'sessionPtr': session_ptr,
            'frontendRequest': answer.get('frontendRequest'),
            'token': self._knocks.seal_session(answer['token'], user_id, room.room_id),
        })


class LinkResultEP(DirectServeJsonResource):
    def __init__(self, knocks: SecuredRoomKnocks):
        super().__init__()
        self._knocks = knocks

    async def _async_render_POST(self, request):
        found = await self._knocks.room_of_link(link_arg(request, b"link"))
        if found is None:
            respond_with_json(request, 400, {'Err': 'InvalidLink'})
            return
        (user_id, room) = found

        answer = await self._knocks.complete(user_id, room, link_arg(request, b"session_token"))
        # Also 200 for an 'Err': yivi-client, which calls this for the page, discards any other
        # status before the page gets to read which error it was.
        respond_with_json(request, 200, answer)


async def switch_secured_rooms_to_knock(module_api: ModuleApi, config: HubClientApiConfig, store: HubStore) -> None:
    """Give existing secured rooms the 'knock' join rule, as new ones get on a standalone hub."""
    for room in await store.get_secured_rooms() or []:
        try:
            state = await module_api.get_room_state(room.room_id, [(EventTypes.JoinRules, "")])
            join_rules = state.get((EventTypes.JoinRules, ""))
            if join_rules is not None and join_rules.content.get("join_rule") == JoinRules.KNOCK:
                continue
            await module_api.create_and_send_event_into_room({
                "type": EventTypes.JoinRules,
                "room_id": room.room_id,
                "sender": config.server_notices_user,
                "state_key": "",
                "content": {"join_rule": JoinRules.KNOCK},
            })
            logger.info(f"secured room {room.room_id} now has join rule 'knock'")
        except Exception as e:
            logger.error(f"could not give secured room {room.room_id} join rule 'knock': {e}")
