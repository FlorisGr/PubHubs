// The Yivi step of the pages a standalone hub serves to users of other Matrix clients (e.g.
// Element), which cannot run a Yivi session themselves. The hub renders the page, with its texts,
// and hands this script what it needs in #config (see modules/pubhubs/_yivi_pages.py):
//   - 'sso': logging in to the hub from a Matrix client (Matrix SSO)
//   - 'room': showing the attributes a secured room asks for, after knocking on it
// All urls are relative to the page, which the hub serves under the endpoints it talks to.
//
// The same Yivi packages (and versions) as the hub client, rather than the all-in-one
// yivi-frontend, which does not export SessionManagement for the relaxation below.
// Yivi's styles are imported by style.css, so that ours come after them.
import './style.css';
import { SessionManagement, YiviClient } from '@privacybydesign/yivi-client';
import { YiviCore } from '@privacybydesign/yivi-core';
import { YiviWeb } from '@privacybydesign/yivi-web';

// yivi-client refuses a plain http session url unless it is on localhost, so that a tampered one
// cannot send the frontend authorization token elsewhere. A development hub is served over http on
// its network address, which that refuses too (the hub client relaxes it the same way, see its
// logic/utils/yiviSessionUrl.ts). Only the page's own origin is let through: as safe as the
// relative urls yivi-client does allow. Production hubs use https and never get here.
const assertSafeSessionUrl = SessionManagement.prototype._assertSafeSessionUrl;
SessionManagement.prototype._assertSafeSessionUrl = function (url) {
	if (typeof url === 'string' && !url.startsWith('//')) {
		try {
			if (new URL(url, window.location.href).origin === window.location.origin) return;
		} catch {
			// the original rejects it
		}
	}
	assertSafeSessionUrl.call(this, url);
};

const config = JSON.parse(document.getElementById('config').textContent);
const status = document.getElementById('status');

const show = (text, kind) => {
	status.textContent = text;
	status.className = kind;
};

const runSession = (start, result) => {
	const core = new YiviCore({
		element: '#yivi',
		language: config.language,
		session: {
			url: new URL('.', window.location.href).href,
			start: {
				url: () => start,
				method: 'POST',
				// A new attempt, e.g. after Yivi's own 'Try again': the last one's message is stale
				parseResponse: (response) => {
					show('', '');
					return response.json();
				},
			},
			result,
		},
	});
	core.use(YiviWeb);
	core.use(YiviClient);
	return core.start();
};

// When the session itself fails to start or is aborted. The sealed state in the url stays valid
// for a while, so starting over is just loading the page again.
const offerRetry = (text) => {
	show(text, 'error');
	const retry = document.createElement('button');
	retry.textContent = config.texts.retry;
	retry.addEventListener('click', () => window.location.reload());
	status.after(retry);
};

const loginForMatrixClient = async () => {
	// Without a result endpoint, resolves with the mapped start response, which holds the sealed token
	const { sessionToken } = await runSession('start', false);
	// A navigation, not a fetch: the hub answers with a redirect to the Matrix client, or a page
	window.location.assign(`sso-complete?${new URLSearchParams({ state: config.state, session_token: sessionToken })}`);
};

const discloseForRoom = async () => {
	const query = new URLSearchParams({ link: config.link });
	const joined = await runSession(`start?${query}`, {
		url: (_o, { sessionToken }) => `result?${new URLSearchParams({ link: config.link, session_token: sessionToken ?? '' })}`,
		method: 'POST',
		parseResponse: async (response) => {
			const body = await response.json();
			if (!body.Ok) {
				// Yivi shows its own generic error with 'Try again', and keeps the session going
				// instead of rejecting, so tell what went wrong here
				show(body.Err === 'NotAllowed' ? config.texts.not_allowed : config.texts.failed, 'error');
				throw new Error(body.Err ?? 'Failed');
			}
			return body.Ok;
		},
	});
	// The Yivi element stays, showing its own 'Success'; the explanation asked to scan
	document.getElementById('explanation').hidden = true;
	show(config.texts.joined, 'ok');
	const open = document.createElement('a');
	open.href = `https://matrix.to/#/${encodeURIComponent(joined.room_id)}`;
	open.textContent = config.texts.open_room;
	status.after(open);
};

(config.page === 'sso' ? loginForMatrixClient() : discloseForRoom()).catch((error) => {
	offerRetry(error instanceof Error && error.message === 'NotAllowed' ? config.texts.not_allowed : config.texts.failed);
});
