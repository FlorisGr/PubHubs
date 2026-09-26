"""Tests for the Yivi pages a standalone hub serves itself (modules/pubhubs/_yivi_pages.py)."""

import json
import re
import sys
import unittest
from unittest import mock

sys.path.append("modules")
from pubhubs._yivi_pages import TEXTS, language_of, origin_of, render_page


def request_with(accept_language):
    request = mock.Mock()
    request.getHeader = lambda name: accept_language
    return request


class LanguageTest(unittest.TestCase):
    def test_follows_the_browser(self):
        self.assertEqual(language_of(request_with("en-GB,en;q=0.9")), "en")
        self.assertEqual(language_of(request_with("nl-NL,nl;q=0.9,en;q=0.8")), "nl")
        self.assertEqual(language_of(request_with("de-DE,en;q=0.5")), "en")

    def test_is_dutch_otherwise(self):
        self.assertEqual(language_of(request_with(None)), "nl")
        self.assertEqual(language_of(request_with("fr")), "nl")
        # not a prefix match on anything starting with 'en'
        self.assertEqual(language_of(request_with("eno")), "nl")

    def test_both_languages_have_every_text(self):
        self.assertEqual(TEXTS["en"].keys(), TEXTS["nl"].keys())


class RenderTest(unittest.TestCase):
    def render(self, **kwargs):
        (page, csp) = render_page(language="en", title="T", heading="H", explanation="E", **kwargs)
        return page.decode(), csp

    def test_escapes_the_texts(self):
        (page, _) = render_page(language="en", title="<t>", heading="<script>x</script>", explanation="\"&")
        page = page.decode()
        self.assertNotIn("<script>x", page)
        self.assertIn("&lt;script&gt;x&lt;/script&gt;", page)
        self.assertIn("&quot;&amp;", page)

    def test_config_cannot_close_its_script_element(self):
        (page, _) = self.render(config={"link": "</script><script>alert(1)</script>"})
        self.assertEqual(page.count("</script>"), 2)
        config = re.search(r'<script type="application/json" id="config">(.*?)</script>', page).group(1)
        self.assertEqual(json.loads(config), {"link": "</script><script>alert(1)</script>"})

    def test_without_config_runs_no_script(self):
        (page, _) = self.render()
        self.assertNotIn("<script", page)

    def test_csp_allows_only_the_hub_and_its_yivi_server(self):
        (_, csp) = self.render(config={}, yivi_origin="https://yivi.example")
        self.assertIn("script-src 'self';", csp)
        self.assertIn("connect-src 'self' https://yivi.example;", csp)
        self.assertIn("frame-ancestors 'none'", csp)

    def test_origin_of(self):
        self.assertEqual(origin_of("https://hub.example:8448/_synapse/"), "https://hub.example:8448")


if __name__ == "__main__":
    unittest.main()
