import html
import json
import logging
import os
from urllib.parse import urlsplit

from twisted.web.resource import NoResource
from twisted.web.static import File

from synapse.http.server import finish_request, set_clickjacking_protection_headers
from synapse.module_api import ModuleApi

logger = logging.getLogger("synapse.contrib." + __name__)

# The pages a standalone hub serves itself to users of other Matrix clients (e.g. Element), for
# the Yivi steps those clients cannot do: logging in (see YiviLogin.py) and showing the attributes
# a secured room asks for (see _secured_room_knock.py).  Served by the hub rather than the hub
# client, so such a hub needs no hub client at all, and the pages share the hub's origin with the
# endpoints and the SSO cookie they use.
#
# The Yivi frontend and the pages' script come from yivi_pages/, which the Dockerfile bundles into
# ASSETS_DIR.

ASSETS_DIR = "/non-persistent-data/assets/yivi_pages"
ASSETS_PATH = "/_synapse/client/.ph/yivi-pages"
# From a page, which is always at /_synapse/client/.ph/<endpoints>/<page>
ASSETS_URL = "../yivi-pages"

LANGUAGES = ("nl", "en")

TEXTS = {
    "en": {
        "sso_title": "Log in with Yivi",
        "sso_explanation": "Scan the QR code with your Yivi app to log in to this hub with your Matrix app. Other members only see your pseudonym.",
        "room_title": "Join a room with Yivi",
        "room_explanation": "The room \"{room}\" is only open to people who show some of their attributes with Yivi. Scan the QR code with your Yivi app: it shows which attributes the room asks for.",
        "invalid_link": "This link has expired or is not valid. Ask to join the room again in your Matrix app to get a new one.",
        "failed": "That did not succeed. Please try again.",
        "not_allowed": "Your Yivi app did not show the attributes this room asks for. Please try again.",
        "retry": "Try again",
        "joined": "You joined \"{room}\". You can go back to your Matrix app.",
        "open_room": "Open the room",
    },
    "nl": {
        "sso_title": "Inloggen met Yivi",
        "sso_explanation": "Scan de QR-code met je Yivi-app om met je Matrix-app in te loggen bij deze hub. Andere leden zien alleen je pseudoniem.",
        "room_title": "Lid worden van een room met Yivi",
        "room_explanation": "De room \"{room}\" is alleen open voor mensen die een deel van hun gegevens laten zien met Yivi. Scan de QR-code met je Yivi-app: die laat zien om welke gegevens de room vraagt.",
        "invalid_link": "Deze link is verlopen of niet geldig. Vraag in je Matrix-app opnieuw om lid te worden van de room om een nieuwe te krijgen.",
        "failed": "Dat is niet gelukt. Probeer het opnieuw.",
        "not_allowed": "Je Yivi-app liet niet de gegevens zien waar deze room om vraagt. Probeer het opnieuw.",
        "retry": "Opnieuw proberen",
        "joined": "Je bent lid geworden van \"{room}\". Je kunt teruggaan naar je Matrix-app.",
        "open_room": "Open de room",
    },
}


def register_assets(api: ModuleApi) -> None:
    if not os.path.isdir(ASSETS_DIR):
        # e.g. a development hub whose image predates yivi_pages
        logger.warning(f"yivi pages: {ASSETS_DIR} is missing, so users of other Matrix clients cannot log in or enter secured rooms; rebuild the hub image")
    assets = File(ASSETS_DIR)
    # just the two files, no directory listing
    assets.directoryListing = lambda: NoResource()
    api.register_web_resource(ASSETS_PATH, assets)


def language_of(request) -> str:
    """The first of LANGUAGES in the browser's Accept-Language, else Dutch, like the hub client."""
    header = (request.getHeader("Accept-Language") or "").lower()
    for part in header.split(","):
        tag = part.split(";")[0].strip()
        for language in LANGUAGES:
            if tag == language or tag.startswith(language + "-"):
                return language
    return "nl"


def texts(language: str) -> dict:
    return TEXTS[language]


def origin_of(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def render_page(*, language: str, title: str, heading: str, explanation: str, config: dict | None = None, yivi_origin: str | None = None) -> tuple[bytes, str]:
    """A page with a Yivi session, run by the bundled script with `config`; without `config` just
    the explanation (e.g. for an invalid link).

    Returns:
        the page, and the Content-Security-Policy for it
    """
    if config is None:
        body = f"<main><h1>{html.escape(heading)}</h1><p>{html.escape(explanation)}</p></main>"
        scripts = ""
    else:
        # In a JSON script element, so no value is ever interpreted as markup or code
        config_json = json.dumps(config).replace("<", "\\u003c")
        body = (
            f"<main><h1>{html.escape(heading)}</h1>"
            f"<p id=\"explanation\">{html.escape(explanation)}</p>"
            # Above the Yivi element, which is tall enough to push anything below it out of view
            "<p id=\"status\" role=\"status\"></p>"
            "<div id=\"yivi\"></div></main>"
        )
        scripts = (
            f"<script type=\"application/json\" id=\"config\">{config_json}</script>"
            f"<script src=\"{ASSETS_URL}/yivi-pages.js\"></script>"
        )

    page = (
        "<!DOCTYPE html>"
        f"<html lang=\"{language}\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>{html.escape(title)}</title>"
        f"<link rel=\"stylesheet\" href=\"{ASSETS_URL}/yivi-pages.css\">"
        f"</head><body>{body}{scripts}</body></html>"
    )

    # The Yivi frontend polls the Yivi server through the hub's proxy, which may be configured on
    # another origin (public_yivi_url).  It sets some styles inline.
    connect = "'self'" + (f" {yivi_origin}" if yivi_origin else "")
    csp = (
        "default-src 'none'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        f"connect-src {connect}; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    )
    return page.encode("utf-8"), csp


def respond_with_page(request, page: tuple[bytes, str], code: int = 200) -> None:
    """Like synapse's respond_with_html_bytes, which replaces any Content-Security-Policy with its
    clickjacking one; `csp` has that frame-ancestors 'none' too."""
    (html_bytes, csp) = page
    request.setResponseCode(code)
    if request._disconnected:
        return
    request.setHeader(b"Content-Type", b"text/html; charset=utf-8")
    request.setHeader(b"Content-Length", b"%d" % (len(html_bytes),))
    request.setHeader(b"Cache-Control", b"no-store")
    set_clickjacking_protection_headers(request)
    request.setHeader(b"Content-Security-Policy", csp.encode("ascii"))
    request.write(html_bytes)
    finish_request(request)
