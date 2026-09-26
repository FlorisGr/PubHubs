"""Tests for the standalone Yivi login (modules/pubhubs/YiviLogin.py)."""

import contextlib
import os
import sys
import tempfile
import time
import unittest
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
    Config,
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


if __name__ == "__main__":
    unittest.main()
