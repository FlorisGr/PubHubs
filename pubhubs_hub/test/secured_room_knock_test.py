"""Tests for letting users of other Matrix clients into secured rooms (modules/pubhubs/_secured_room_knock.py)."""

import sys
import time
import unittest
from unittest import IsolatedAsyncioTestCase, mock
from urllib.parse import parse_qs, urlsplit

import nacl.utils

sys.path.append("modules")
from pubhubs._secured_room_knock import (
    LINK_LIFETIME_SECONDS,
    LINK_PAGE_PATH,
    LinkPageEP,
    LinkResultEP,
    SESSION_TIMEOUT_SECONDS,
    SecuredRoomKnocks,
    grant_access,
    invite_to_knock_room,
    switch_secured_rooms_to_knock,
)
from pubhubs._secured_rooms_class import PubHubsSecuredRoomType, SecuredRoom

knock_module = sys.modules["pubhubs._secured_room_knock"]

NOTICES = "@notices_user:hub"
ALICE = "@alice:hub"
EMAIL = "pbdf.sidn-pbdf.email.email"


def secured_room(room_id="!room:hub", accepted_values=None):
    return SecuredRoom(
        name="Staff",
        topic="",
        accepted={EMAIL: {"profile": False, "accepted_values": accepted_values or []}},
        user_txt="",
        type=PubHubsSecuredRoomType.MESSAGES,
        room_id=room_id,
    )


def disclosure(value="alice@example.com", proof="VALID"):
    return {"status": "DONE", "proofStatus": proof, "disclosed": [[{"id": EMAIL, "rawvalue": value, "status": "PRESENT"}]]}


class FakeEvent:
    def __init__(self, content, sender=None, state_key=None, type="m.room.member", room_id="!room:hub"):
        self.content = content
        self.sender = sender
        self.state_key = state_key
        self.type = type
        self.room_id = room_id


def knock(user=ALICE, sender=None, room_id="!room:hub"):
    return FakeEvent({"membership": "knock"}, sender=sender or user, state_key=user, room_id=room_id)


class FakeConfig:
    hub_name = "My hub"
    server_notices_user = NOTICES
    yivi_url_web = "http://yivi:8089"
    public_yivi_url = "https://hub.example/"


class FakeStore:
    def __init__(self, rooms=(), allowed=()):
        self.rooms = {r.room_id: r for r in rooms}
        self.allowed = set(allowed)

    async def get_secured_room(self, room_id):
        return self.rooms.get(room_id)

    async def get_secured_rooms(self):
        return list(self.rooms.values())

    async def is_allowed(self, user_id, room_id):
        return (user_id, room_id) in self.allowed

    async def allow(self, user_id, room_id, join_time):
        self.allowed.add((user_id, room_id))


class FakeApi:
    def __init__(self, join_rule="knock", membership=None, admins=()):
        self.join_rule = join_rule
        self.membership = membership
        self.admins = set(admins)
        self.memberships = []
        self.sent = []
        self.notices = []
        self.http_client = mock.Mock()
        self.http_client.get_json = mock.AsyncMock(return_value=disclosure())
        notices = mock.Mock()
        notices.send_notice = mock.AsyncMock(side_effect=lambda user, content: self.notices.append((user, content)))
        self._hs = mock.Mock()
        self._hs.get_server_notices_manager.return_value = notices

    public_baseurl = "https://hub.example/"

    def is_mine(self, user_id):
        return user_id.endswith(":hub")

    async def is_user_admin(self, user_id):
        return user_id in self.admins

    async def get_room_state(self, room_id, types):
        state = {}
        if self.join_rule is not None:
            state[("m.room.join_rules", "")] = FakeEvent({"join_rule": self.join_rule})
        if self.membership is not None:
            state[("m.room.member", ALICE)] = FakeEvent({"membership": self.membership})
        return state

    async def update_room_membership(self, sender, target, room_id, membership):
        self.memberships.append((sender, target, room_id, membership))

    async def create_and_send_event_into_room(self, event):
        self.sent.append(event)


def knocks(api=None, store=None):
    return SecuredRoomKnocks(api or FakeApi(), FakeConfig(), store or FakeStore([secured_room()]), nacl.utils.random(32))


def link_of(url):
    return parse_qs(urlsplit(url).query)["link"][0]


class LinkTest(unittest.TestCase):
    def test_round_trips(self):
        k = knocks()
        self.assertEqual(k.unseal_link(k.seal_link(ALICE, "!room:hub")), (ALICE, "!room:hub"))

    def test_survives_a_restart(self):
        # sealed with the key handed in (derived from the macaroon secret), not an ephemeral one
        key = nacl.utils.random(32)
        a = SecuredRoomKnocks(FakeApi(), FakeConfig(), FakeStore(), key)
        b = SecuredRoomKnocks(FakeApi(), FakeConfig(), FakeStore(), key)
        self.assertEqual(b.unseal_link(a.seal_link(ALICE, "!room:hub")), (ALICE, "!room:hub"))

    def test_rejects_another_hubs_link(self):
        self.assertIsNone(knocks().unseal_link(knocks().seal_link(ALICE, "!room:hub")))

    def test_rejects_tampering(self):
        k = knocks()
        sealed = k.seal_link(ALICE, "!room:hub")
        self.assertIsNone(k.unseal_link(sealed[:-2] + ("AA" if sealed[-2:] != "AA" else "BB")))

    def test_expires(self):
        k = knocks()
        sealed = k.seal_link(ALICE, "!room:hub")
        with mock.patch.object(knock_module.time, "time", return_value=time.time() + LINK_LIFETIME_SECONDS + 1):
            self.assertIsNone(k.unseal_link(sealed))

    def test_is_a_page_of_the_hub(self):
        parts = urlsplit(knocks().link_url(ALICE, "!room:hub"))
        self.assertEqual((parts.scheme, parts.netloc, parts.path), ("https", "hub.example", LINK_PAGE_PATH))

    def test_a_link_is_not_a_session(self):
        k = knocks()
        self.assertIsNone(k.unseal_session(k.seal_link(ALICE, "!room:hub"), ALICE, "!room:hub"))


class SessionTest(unittest.TestCase):
    def test_is_bound_to_the_links_user_and_room(self):
        k = knocks()
        sealed = k.seal_session("abc", ALICE, "!room:hub")
        self.assertEqual(k.unseal_session(sealed, ALICE, "!room:hub"), "abc")
        self.assertIsNone(k.unseal_session(sealed, "@bob:hub", "!room:hub"))
        self.assertIsNone(k.unseal_session(sealed, ALICE, "!other:hub"))

    def test_expires(self):
        k = knocks()
        sealed = k.seal_session("abc", ALICE, "!room:hub")
        with mock.patch.object(knock_module.time, "time", return_value=time.time() + SESSION_TIMEOUT_SECONDS + 1):
            self.assertIsNone(k.unseal_session(sealed, ALICE, "!room:hub"))

    def test_rejects_odd_requestor_tokens(self):
        k = knocks()
        self.assertIsNone(k.unseal_session(k.seal_session("../admin", ALICE, "!room:hub"), ALICE, "!room:hub"))

    def test_a_result_is_used_once(self):
        k = knocks()
        self.assertTrue(k.consume("abc"))
        self.assertFalse(k.consume("abc"))


class KnockTest(IsolatedAsyncioTestCase):
    async def test_sends_a_link_to_whoever_still_has_to_disclose(self):
        api = FakeApi()
        k = knocks(api)
        await k.on_new_event(knock(), {})
        [(user, content)] = api.notices
        self.assertEqual(user, ALICE)
        self.assertIn("Staff", content["body"])
        link = link_of(content["body"].split()[-1])
        self.assertEqual(k.unseal_link(link), (ALICE, "!room:hub"))
        self.assertEqual(api.memberships, [])

    async def test_invites_who_was_let_in_before(self):
        api = FakeApi()
        await knocks(api, FakeStore([secured_room()], allowed=[(ALICE, "!room:hub")])).on_new_event(knock(), {})
        self.assertEqual(api.memberships, [(NOTICES, ALICE, "!room:hub", "invite")])
        self.assertEqual(api.notices, [])

    async def test_invites_hub_admins(self):
        api = FakeApi(admins=[ALICE])
        await knocks(api).on_new_event(knock(), {})
        self.assertEqual(api.memberships, [(NOTICES, ALICE, "!room:hub", "invite")])
        self.assertEqual(api.notices, [])

    async def test_ignores_other_events(self):
        api = FakeApi()
        k = knocks(api)
        await k.on_new_event(FakeEvent({"membership": "join"}, sender=ALICE, state_key=ALICE), {})
        await k.on_new_event(FakeEvent({"body": "hi"}, sender=ALICE, type="m.room.message"), {})
        # a knock on a room that isn't secured
        await k.on_new_event(knock(room_id="!plain:hub"), {})
        # remote users get no notice: they're not ours to send one to
        await k.on_new_event(knock(user="@alice:elsewhere"), {})
        self.assertEqual((api.notices, api.memberships), ([], []))


class InviteTest(IsolatedAsyncioTestCase):
    async def test_invites_to_a_knock_room(self):
        api = FakeApi(join_rule="knock", membership="knock")
        await invite_to_knock_room(api, FakeConfig(), ALICE, "!room:hub")
        self.assertEqual(api.memberships, [(NOTICES, ALICE, "!room:hub", "invite")])

    async def test_leaves_public_rooms_alone(self):
        # those the user just joins, as before
        api = FakeApi(join_rule="public")
        await invite_to_knock_room(api, FakeConfig(), ALICE, "!room:hub")
        self.assertEqual(api.memberships, [])

    async def test_leaves_members_and_invitees_alone(self):
        for membership in ("join", "invite"):
            with self.subTest(membership=membership):
                api = FakeApi(membership=membership)
                await invite_to_knock_room(api, FakeConfig(), ALICE, "!room:hub")
                self.assertEqual(api.memberships, [])

    async def test_survives_a_refused_invite(self):
        api = FakeApi(membership="ban")
        api.update_room_membership = mock.AsyncMock(side_effect=Exception("banned"))
        await invite_to_knock_room(api, FakeConfig(), ALICE, "!room:hub")

    async def test_grant_access_keeps_the_notice_the_hub_client_parses(self):
        api = FakeApi()
        store = FakeStore()
        await grant_access(api, FakeConfig(), store, ALICE, "!room:hub", {EMAIL: ""})
        self.assertIn((ALICE, "!room:hub"), store.allowed)
        self.assertEqual(api.sent[0]["content"]["body"], f"{ALICE} joined the room with attributes {{'{EMAIL}': ''}}")
        self.assertEqual(api.sent[0]["sender"], NOTICES)
        self.assertEqual(api.memberships, [(NOTICES, ALICE, "!room:hub", "invite")])


class CompleteTest(IsolatedAsyncioTestCase):
    def setUp(self):
        self.api = FakeApi()
        self.store = FakeStore([secured_room(accepted_values=["alice@example.com"])])
        self.k = knocks(self.api, self.store)
        self.room = self.store.rooms["!room:hub"]

    async def complete(self, token="abc", user=ALICE, room_id="!room:hub"):
        return await self.k.complete(ALICE, self.room, self.k.seal_session(token, user, room_id))

    async def test_lets_the_user_in_and_joins_them(self):
        answer = await self.complete()
        self.assertEqual(answer, {"Ok": {"room_id": "!room:hub", "room_name": "Staff"}})
        self.assertIn((ALICE, "!room:hub"), self.store.allowed)
        self.assertEqual(self.api.memberships, [(NOTICES, ALICE, "!room:hub", "invite"), (ALICE, ALICE, "!room:hub", "join")])

    async def test_refuses_a_disclosure_that_does_not_fit(self):
        self.api.http_client.get_json.return_value = disclosure(value="mallory@example.com")
        self.assertEqual(await self.complete(), {"Err": "NotAllowed"})
        self.assertEqual((self.store.allowed, self.api.memberships), (set(), []))

    async def test_refuses_a_session_started_for_someone_else(self):
        self.assertEqual(await self.complete(user="@bob:hub"), {"Err": "BadRequest"})
        self.api.http_client.get_json.assert_not_called()

    async def test_a_disclosure_is_used_once(self):
        await self.complete()
        self.assertEqual(await self.complete(), {"Err": "BadRequest"})

    async def test_keeps_the_invite_when_joining_fails(self):
        calls = []

        async def update_room_membership(sender, target, room_id, membership):
            calls.append(membership)
            if membership == "join":
                raise Exception("nope")

        self.api.update_room_membership = update_room_membership
        self.assertIn("Ok", await self.complete())
        self.assertEqual(calls, ["invite", "join"])


class LinkPageTest(IsolatedAsyncioTestCase):
    def setUp(self):
        self.k = knocks(store=FakeStore([secured_room()]))
        self.endpoint = object.__new__(LinkPageEP)
        self.endpoint._knocks = self.k
        self.pages = []
        patcher = mock.patch.object(knock_module, "respond_with_page", lambda request, page, code=200: self.pages.append((page, code)))
        patcher.start()
        self.addCleanup(patcher.stop)

    def request(self, link):
        request = mock.Mock()
        request.args = {b"link": [link.encode()]}
        request.getHeader = lambda name: "en"
        return request

    async def test_runs_the_disclosure_for_the_room(self):
        link = self.k.seal_link(ALICE, "!room:hub")
        await self.endpoint._async_render_GET(self.request(link))
        [((html, _), code)] = self.pages
        html = html.decode()
        self.assertEqual(code, 200)
        self.assertIn("The room &quot;Staff&quot; is only open", html)
        self.assertIn(link, html)
        self.assertIn('You joined \\"Staff\\"', html)

    async def test_explains_an_invalid_link(self):
        for link in ("nonsense", self.k.seal_link(ALICE, "!gone:hub")):
            with self.subTest(link=link):
                self.pages.clear()
                await self.endpoint._async_render_GET(self.request(link))
                [((html, _), code)] = self.pages
                self.assertEqual(code, 400)
                self.assertIn("This link has expired or is not valid", html.decode())
                self.assertNotIn("yivi-pages.js", html.decode())


class LinkResultTest(IsolatedAsyncioTestCase):
    async def test_answers_200_also_for_a_refusal(self):
        # yivi-client discards any other status before the page can read which error it was
        api = FakeApi()
        api.http_client.get_json.return_value = disclosure(value="mallory@example.com")
        k = knocks(api, FakeStore([secured_room(accepted_values=["alice@example.com"])]))
        endpoint = object.__new__(LinkResultEP)
        endpoint._knocks = k
        request = mock.Mock()
        request.args = {b"link": [k.seal_link(ALICE, "!room:hub").encode()], b"session_token": [k.seal_session("abc", ALICE, "!room:hub").encode()]}
        answers = []
        with mock.patch.object(knock_module, "respond_with_json", lambda request, code, body: answers.append((code, body))):
            await endpoint._async_render_POST(request)
        self.assertEqual(answers, [(200, {"Err": "NotAllowed"})])


class SwitchTest(IsolatedAsyncioTestCase):
    async def test_switches_public_secured_rooms_to_knock(self):
        api = FakeApi(join_rule="public")
        await switch_secured_rooms_to_knock(api, FakeConfig(), FakeStore([secured_room()]))
        [event] = api.sent
        self.assertEqual((event["type"], event["state_key"], event["content"], event["sender"]), ("m.room.join_rules", "", {"join_rule": "knock"}, NOTICES))

    async def test_leaves_knock_rooms_alone(self):
        api = FakeApi(join_rule="knock")
        await switch_secured_rooms_to_knock(api, FakeConfig(), FakeStore([secured_room()]))
        self.assertEqual(api.sent, [])

    async def test_goes_on_after_a_failing_room(self):
        api = FakeApi(join_rule="public")
        sent = []

        async def create_and_send_event_into_room(event):
            if event["room_id"] == "!a:hub":
                raise Exception("no power")
            sent.append(event["room_id"])

        api.create_and_send_event_into_room = create_and_send_event_into_room
        await switch_secured_rooms_to_knock(api, FakeConfig(), FakeStore([secured_room("!a:hub"), secured_room("!b:hub")]))
        self.assertEqual(sent, ["!b:hub"])


if __name__ == "__main__":
    unittest.main()
