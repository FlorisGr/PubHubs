// Packages
import { YiviClient } from '@privacybydesign/yivi-client';
import { YiviCore } from '@privacybydesign/yivi-core';
import { YiviWeb } from '@privacybydesign/yivi-web';

// Assets
import '@hub-client/assets/yivi.min.css';

import { CONFIG } from '@hub-client/logic/logging/Config';
import { getLogLevel } from '@hub-client/logic/logging/Logger';
import { allowInsecureYiviSessionUrlsInDev } from '@hub-client/logic/utils/yiviSessionUrl';

// Types
type LinkedHub = {
	description?: string;
	name: string;
	url: string;
};

type StandaloneInfo = {
	attribute: string;
	hub_name: string;
	linked_hubs: LinkedHub[];
};

type StandaloneLoginResult = {
	access_token: string;
	device_id: string;
	mxid: string;
	new_user: boolean;
};

const loginUrl = `${CONFIG._env.HUB_URL}/_synapse/client/.ph/yivi-login`;

allowInsecureYiviSessionUrlsInDev();

/**
 * Asks the hub whether it runs standalone, i.e. has its own Yivi login instead of PubHubs Central.
 *
 * @returns the hub's login info, or null for a hub that is entered through PubHubs Central
 */
const fetchStandaloneInfo = async (): Promise<StandaloneInfo | null> => {
	try {
		const response = await fetch(`${loginUrl}/info`);
		// Hubs without the YiviLogin module answer 404
		if (!response.ok) return null;
		const body = (await response.json()) as { Ok?: StandaloneInfo };
		return body.Ok ?? null;
	} catch {
		return null;
	}
};

/**
 * Shows a Yivi QR code (or app link on mobile) in `elementId`, and resolves once the user disclosed
 * the hub's login attribute and the hub logged them in.
 *
 * @param elementId css selector of the element the Yivi frontend renders in
 * @param language
 */
const yiviLogin = async (elementId: string, language: 'nl' | 'en' | undefined): Promise<StandaloneLoginResult> => {
	const session = new YiviCore({
		debugging: getLogLevel() === 'debug',
		element: elementId,
		language,
		session: {
			url: loginUrl,
			start: {
				url: () => `${loginUrl}/start`,
				method: 'POST',
			},
			result: {
				// The token is sealed by the hub; only the hub can use it to fetch the disclosure
				url: (_o: unknown, obj: { sessionToken?: string }) => `${loginUrl}/result?session_token=${encodeURIComponent(obj.sessionToken ?? '')}`,
				method: 'POST',
				parseResponse: async (response: Response) => {
					const body = (await response.json()) as { Ok?: StandaloneLoginResult; Err?: string };
					if (!body.Ok) throw new Error(body.Err ?? 'Login failed');
					return body.Ok;
				},
			},
		},
	});

	session.use(YiviWeb);
	session.use(YiviClient);

	return (await session.start()) as StandaloneLoginResult;
};

export { fetchStandaloneInfo, yiviLogin, LinkedHub, StandaloneInfo, StandaloneLoginResult };
