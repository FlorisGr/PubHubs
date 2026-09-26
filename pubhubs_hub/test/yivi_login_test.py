"""Tests for the standalone Yivi login (modules/pubhubs/YiviLogin.py)."""

import contextlib
import os
import sys
import tempfile
import time
import unittest
from urllib.parse import parse_qs, urlsplit
from unittest import IsolatedAsyncioTestCase
from unittest import mock

import nacl.secret
import nacl.utils

from synapse.module_api.errors import ConfigError

sys.path.append("modules")
import pubhubs.YiviLogin

# the package re-exports the class under the module's name, so fetch the module itself
yivi_login_module = sys.modules["pubhubs.YiviLogin"]
from pubhubs.YiviLogin import (
    LOGIN_TIMEOUT_SECONDS,
    SSO_COOKIE,
    SSO_PAGE_PATH,
    Config,
    SsoCompleteEP,
    SsoPageEP,
    YiviIdentityProvider,
    YiviLogin,
    check_result,
    load_or_create_key,
)

EMAIL = "pbdf.sidn-pbdf.email.email"


def done_result(value="alice@example.com", attribute=EMAIL, proof="VALID", status="PRESENT"):
    return {
        "status": "DONE",
        "proofStatus": proof,
        "disclosed": [[{"id": attribute, "rawvalue": value, "status": status}]],
    }


def bare_login(key=b"k" * 32, attribute=EMAIL) -> YiviLogin:
    """A YiviLogin with just the state its pure methods need, without a homeserver."""
    login = object.__new__(YiviLogin)
    login._config = Config(attribute=attribute)
    login._pseudonym_key = key
    login._secret_box = nacl.secret.Aead(nacl.utils.random(nacl.secret.Aead.KEY_SIZE))
    login._consumed = {}
    return login


class CheckResultTest(unittest.TestCase):
    def test_accepts_a_valid_disclosure(self):
        self.assertEqual(check_result(done_result(), EMAIL), "alice@example.com")

    def test_rejects_an_unfinished_session(self):
        result = done_result()
        result["status"] = "CONNECTED"
        self.assertIsNone(check_result(result, EMAIL))

    def test_rejects_an_invalid_proof(self):
        for proof in ("EXPIRED", "INVALID", "MISSING_ATTRIBUTES", None):
            with self.subTest(proof=proof):
                self.assertIsNone(check_result(done_result(proof=proof), EMAIL))

    def test_rejects_another_attribute(self):
        self.assertIsNone(check_result(done_result(attribute="pbdf.gemeente.personalData.bsn"), EMAIL))

    def test_rejects_an_absent_attribute(self):
        self.assertIsNone(check_result(done_result(status="NULL"), EMAIL))

    def test_rejects_an_empty_value(self):
        self.assertIsNone(check_result(done_result(value="  "), EMAIL))

    def test_rejects_a_missing_disclosure(self):
        self.assertIsNone(check_result({"status": "DONE", "proofStatus": "VALID"}, EMAIL))


class PseudonymTest(unittest.TestCase):
    def test_is_stable(self):
        self.assertEqual(bare_login().pseudonym("alice@example.com"), bare_login().pseudonym("alice@example.com"))

    def test_emails_are_normalized(self):
        login = bare_login()
        self.assertEqual(login.pseudonym(" Alice@Example.com"), login.pseudonym("alice@example.com"))

    def test_other_attributes_keep_their_case(self):
        login = bare_login(attribute="irma-demo.MijnOverheid.fullName.firstname")
        self.assertNotEqual(login.pseudonym("Alice"), login.pseudonym("alice"))

    def test_differs_per_hub(self):
        self.assertNotEqual(bare_login(key=b"a" * 32).pseudonym("x"), bare_login(key=b"b" * 32).pseudonym("x"))

    def test_differs_per_attribute(self):
        self.assertNotEqual(
            bare_login(attribute=EMAIL).pseudonym("x"),
            bare_login(attribute="pbdf.sidn-pbdf.mobilenumber.mobilenumber").pseudonym("x"),
        )

    def test_does_not_contain_the_value(self):
        self.assertNotIn("alice", bare_login().pseudonym("alice@example.com"))


class SealedTokenTest(unittest.TestCase):
    def test_round_trips(self):
        login = bare_login()
        self.assertEqual(login.unseal_token(login.seal_token("abc")), "abc")

    def test_rejects_tampering(self):
        login = bare_login()
        sealed = login.seal_token("abc")
        tampered = sealed[:-2] + ("AA" if sealed[-2:] != "AA" else "BB")
        self.assertIsNone(login.unseal_token(tampered))

    def test_rejects_a_plain_requestor_token(self):
        self.assertIsNone(bare_login().unseal_token("abcdefghijklmnopqrst"))

    def test_rejects_another_hubs_seal(self):
        self.assertIsNone(bare_login().unseal_token(bare_login().seal_token("abc")))

    def test_expires(self):
        login = bare_login()
        sealed = login.seal_token("abc")
        with mock.patch.object(yivi_login_module.time, "time", return_value=time.time() + LOGIN_TIMEOUT_SECONDS + 1):
            self.assertIsNone(login.unseal_token(sealed))


class ConsumeTest(unittest.TestCase):
    def test_a_result_is_used_once(self):
        login = bare_login()
        self.assertTrue(login.consume("abc"))
        self.assertFalse(login.consume("abc"))
        self.assertTrue(login.consume("def"))


class KeyTest(unittest.TestCase):
    def test_is_generated_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "key")
            key = load_or_create_key(path)
            self.assertEqual(len(key), 32)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            self.assertEqual(load_or_create_key(path), key)

    def test_rejects_a_truncated_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "key")
            with open(path, "wb") as f:
                f.write(b"short")
            with self.assertRaises(ConfigError):
                load_or_create_key(path)


class ParseConfigTest(unittest.TestCase):
    def test_defaults(self):
        self.assertEqual(YiviLogin.parse_config(None).attribute, EMAIL)

    def test_rejects_a_partial_attribute_id(self):
        with self.assertRaises(ConfigError):
            YiviLogin.parse_config({"attribute": "email"})

    def test_rejects_non_http_linked_hubs(self):
        with self.assertRaises(ConfigError):
            YiviLogin.parse_config({"linked_hubs": [{"name": "x", "url": "javascript:alert(1)"}]})

    def test_accepts_linked_hubs(self):
        hubs = [{"name": "Other hub", "url": "https://other.example.org", "description": "hi"}]
        self.assertEqual(YiviLogin.parse_config({"linked_hubs": hubs}).linked_hubs, hubs)


class FakeStore:
    def __init__(self):
        self.external_ids = {}
        self.deactivated = set()

    async def get_user_by_external_id(self, provider, external_id):
        return self.external_ids.get((provider, external_id))

    async def get_user_deactivated_status(self, mxid):
        return mxid in self.deactivated


class FakeApi:
    def __init__(self):
        self._store = FakeStore()
        self.registered = []

    async def register_user(self, localpart, displayname, emails, admin):
        self.registered.append(localpart)
        return f"@{localpart}:hub"

    async def record_user_external_id(self, provider, external_id, mxid):
        self._store.external_ids[(provider, external_id)] = mxid

    async def register_device(self, mxid):
        return ("DEVICE", "token-" + mxid, None, None)


class FakeLinearizer:
    def queue(self, key):
        return contextlib.AsyncExitStack()


class FakePseudonyms:
    """Stands in for conf.modules.pseudonyms, which only exists inside the container."""

    @staticmethod
    async def register_under_fresh_pseudonym(longlocalpart, register_user):
        return await register_user(longlocalpart[:8])


class LoginTest(IsolatedAsyncioTestCase):
    def setUp(self):
        self.login = bare_login()
        self.login._api = FakeApi()
        self.login._linearizer = FakeLinearizer()
        conf = mock.MagicMock()
        conf.modules.pseudonyms = FakePseudonyms
        patcher = mock.patch.object(yivi_login_module, "conf", conf, create=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    async def test_first_login_registers_a_user(self):
        answer = await self.login.login("p1")
        self.assertTrue(answer["Ok"]["new_user"])
        self.assertEqual(len(self.login._api.registered), 1)

    async def test_next_login_finds_the_same_user(self):
        first = await self.login.login("p1")
        second = await self.login.login("p1")
        self.assertFalse(second["Ok"]["new_user"])
        self.assertEqual(first["Ok"]["mxid"], second["Ok"]["mxid"])
        self.assertEqual(len(self.login._api.registered), 1)

    async def test_localpart_is_not_derived_from_the_pseudonym(self):
        a = await self.login.login("p1")
        self.login._api._store.external_ids.clear()
        b = await self.login.login("p1")
        self.assertNotEqual(a["Ok"]["mxid"], b["Ok"]["mxid"])

    async def test_deactivated_user_cannot_log_in(self):
        mxid = (await self.login.login("p1"))["Ok"]["mxid"]
        self.login._api._store.deactivated.add(mxid)
        self.assertEqual(await self.login.login("p1"), {"Err": "Deactivated"})


class SsoStateTest(unittest.TestCase):
    def test_round_trips(self):
        login = bare_login()
        state = login.unseal_sso_state(login.seal_sso_state("n", "https://app.element.io/", None))
        self.assertEqual((state["nonce"], state["redirect"], state["uia"]), ("n", "https://app.element.io/", None))

    def test_rejects_a_sealed_requestor_token(self):
        # the two seals must not be interchangeable
        login = bare_login()
        self.assertIsNone(login.unseal_sso_state(login.seal_token("abc")))
        self.assertIsNone(login.unseal_token(login.seal_sso_state("n", "https://x/", None)))

    def test_expires(self):
        login = bare_login()
        sealed = login.seal_sso_state("n", "https://x/", None)
        with mock.patch.object(yivi_login_module.time, "time", return_value=time.time() + LOGIN_TIMEOUT_SECONDS + 1):
            self.assertIsNone(login.unseal_sso_state(sealed))


class FakeRequest:
    def __init__(self, args=None, cookies=None):
        self.args = args or {}
        self.cookies = cookies or {}
        self.set_cookie_headers = []
        self.added_cookies = []
        self.responseHeaders = mock.Mock()
        self.responseHeaders.addRawHeader = lambda name, value: self.set_cookie_headers.append(value.decode())

    def getCookie(self, name):
        return self.cookies.get(name)

    def addCookie(self, name, value, **kwargs):
        self.added_cookies.append((name, value, kwargs))


class IdentityProviderTest(IsolatedAsyncioTestCase):
    async def redirect(self, secure=True, client_redirect_url=b"https://app.element.io/#/home", uia=None):
        login = bare_login()
        idp = YiviIdentityProvider(login, page_url="https://hub.example" + SSO_PAGE_PATH, secure_cookie=secure)
        request = FakeRequest()
        url = await idp.handle_redirect_request(request, client_redirect_url, uia)
        return login, request, url

    async def test_sends_the_browser_to_the_hubs_page_with_the_sealed_state(self):
        login, request, url = await self.redirect()
        parts = urlsplit(url)
        self.assertEqual((parts.scheme, parts.netloc, parts.path), ("https", "hub.example", SSO_PAGE_PATH))
        state = login.unseal_sso_state(parse_qs(parts.query)["state"][0])
        self.assertEqual(state["redirect"], "https://app.element.io/#/home")
        self.assertIsNone(state["uia"])

    async def test_binds_the_login_to_the_browser(self):
        login, request, url = await self.redirect()
        state = login.unseal_sso_state(parse_qs(urlsplit(url).query)["state"][0])
        [cookie] = request.set_cookie_headers
        self.assertTrue(cookie.startswith(f"{SSO_COOKIE}={state['nonce']};"))
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)
        self.assertIn("Secure", cookie)

    async def test_cookie_is_not_secure_over_http(self):
        _, request, _ = await self.redirect(secure=False)
        self.assertNotIn("Secure", request.set_cookie_headers[0])

    async def test_nonces_differ(self):
        a = (await self.redirect())[1].set_cookie_headers[0]
        b = (await self.redirect())[1].set_cookie_headers[0]
        self.assertNotEqual(a, b)

    async def test_carries_a_ui_auth_session(self):
        login, _, url = await self.redirect(client_redirect_url=None, uia="uia-session")
        state = login.unseal_sso_state(parse_qs(urlsplit(url).query)["state"][0])
        self.assertEqual((state["redirect"], state["uia"]), (None, "uia-session"))


class SsoPageTest(IsolatedAsyncioTestCase):
    def setUp(self):
        self.login = bare_login()
        self.login._config.hub_name = "My <hub>"
        self.login._public_yivi_url = "https://yivi.hub.example/"
        self.login._api = mock.Mock()
        self.sso_handler = FakeSsoHandler()
        self.login._api._hs.get_sso_handler.return_value = self.sso_handler
        self.endpoint = object.__new__(SsoPageEP)
        self.endpoint._login = self.login
        self.pages = []
        patcher = mock.patch.object(yivi_login_module, "respond_with_page", lambda request, page, code=200: self.pages.append((page, code)))
        patcher.start()
        self.addCleanup(patcher.stop)

    def request(self, state, language="en"):
        request = FakeRequest({b"state": [state.encode()]})
        request.getHeader = lambda name: language
        return request

    async def test_runs_the_login_with_the_state(self):
        state = self.login.seal_sso_state("n", "https://app.element.io/", None)
        await self.endpoint._async_render_GET(self.request(state))
        [((html, csp), code)] = self.pages
        html = html.decode()
        self.assertEqual(code, 200)
        self.assertIn("My &lt;hub&gt;", html)
        self.assertIn(state, html)
        self.assertIn('"page": "sso"', html)
        self.assertIn("connect-src 'self' https://yivi.hub.example", csp)

    async def test_speaks_dutch_when_asked(self):
        await self.endpoint._async_render_GET(self.request(self.login.seal_sso_state("n", "https://x/", None), "nl-NL,nl;q=0.9"))
        self.assertIn("Inloggen met Yivi", self.pages[0][0][0].decode())

    async def test_refuses_an_invalid_state(self):
        await self.endpoint._async_render_GET(self.request("forged"))
        self.assertEqual(self.pages, [])
        self.assertEqual(self.sso_handler.errors, [("invalid_session", 400)])


class FakeSsoHandler:
    def __init__(self):
        self.errors = []
        self.ui_auth = []

    def render_error(self, request, error, error_description=None, code=400):
        self.errors.append((error, code))

    async def complete_sso_ui_auth_request(self, provider, remote_user_id, session_id, request):
        self.ui_auth.append((provider, remote_user_id, session_id))


class SsoCompleteTest(IsolatedAsyncioTestCase):
    def setUp(self):
        self.login = bare_login()
        self.api = FakeApi()
        self.api.completed = []
        self.sso_handler = FakeSsoHandler()
        self.api._hs = mock.Mock()
        self.api._hs.get_sso_handler.return_value = self.sso_handler
        self.api.http_client = mock.Mock()
        self.api.http_client.get_json = mock.AsyncMock(return_value=done_result())

        async def complete_sso_login_async(mxid, request, redirect, new_user=False, auth_provider_id=None):
            self.api.completed.append((mxid, redirect, new_user, auth_provider_id))

        self.api.complete_sso_login_async = complete_sso_login_async
        self.login._api = self.api
        self.login._linearizer = FakeLinearizer()
        conf = mock.MagicMock()
        conf.modules.pseudonyms = FakePseudonyms
        patcher = mock.patch.object(yivi_login_module, "conf", conf, create=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.endpoint = object.__new__(SsoCompleteEP)
        self.endpoint._login = self.login

    def request(self, nonce="nonce", cookie="nonce", redirect="https://app.element.io/", uia=None, token="abc"):
        args = {
            b"state": [self.login.seal_sso_state(nonce, redirect, uia).encode()],
            b"session_token": [self.login.seal_token(token).encode()],
        }
        cookies = {SSO_COOKIE.encode(): cookie.encode()} if cookie is not None else {}
        return FakeRequest(args, cookies)

    async def test_logs_in_and_returns_to_the_matrix_client(self):
        request = self.request()
        await self.endpoint._async_render_GET(request)
        [(mxid, redirect, new_user, provider)] = self.api.completed
        self.assertEqual((redirect, new_user, provider), ("https://app.element.io/", True, "yivi"))
        self.assertEqual(self.sso_handler.errors, [])
        # the cookie is cleared
        self.assertEqual(request.added_cookies[0][:2], (SSO_COOKIE, ""))

    async def test_finds_the_same_user_as_the_hub_clients_own_login(self):
        own = await self.login.login(self.login.pseudonym("alice@example.com"))
        await self.endpoint._async_render_GET(self.request())
        self.assertEqual(self.api.completed[0][0], own["Ok"]["mxid"])
        self.assertFalse(self.api.completed[0][2])

    async def test_refuses_another_browser(self):
        for cookie in (None, "other"):
            with self.subTest(cookie=cookie):
                await self.endpoint._async_render_GET(self.request(cookie=cookie))
        self.assertEqual(self.api.completed, [])
        self.assertEqual([e for e, _ in self.sso_handler.errors], ["invalid_session", "invalid_session"])
        # nothing was fetched, so the Yivi result stays unused
        self.api.http_client.get_json.assert_not_called()

    async def test_refuses_a_forged_state(self):
        request = self.request()
        request.args[b"state"] = [b"forged"]
        await self.endpoint._async_render_GET(request)
        self.assertEqual(self.api.completed, [])
        self.assertEqual(self.sso_handler.errors, [("invalid_session", 400)])

    async def test_refuses_an_unfinished_disclosure(self):
        self.api.http_client.get_json.return_value = {"status": "CONNECTED"}
        await self.endpoint._async_render_GET(self.request())
        self.assertEqual(self.api.completed, [])
        self.assertEqual(self.sso_handler.errors, [("not_disclosed", 403)])

    async def test_a_disclosure_logs_in_once(self):
        await self.endpoint._async_render_GET(self.request())
        await self.endpoint._async_render_GET(self.request())
        self.assertEqual(len(self.api.completed), 1)
        self.assertEqual(self.sso_handler.errors, [("not_disclosed", 403)])

    async def test_completes_ui_auth_without_registering(self):
        await self.endpoint._async_render_GET(self.request(redirect=None, uia="uia-session"))
        self.assertEqual(self.sso_handler.ui_auth, [("yivi", self.login.pseudonym("alice@example.com"), "uia-session")])
        self.assertEqual(self.api.completed, [])
        self.assertEqual(self.api.registered, [])


if __name__ == "__main__":
    unittest.main()
