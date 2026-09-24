/**
 * Info about a standalone hub: one that users log in to with Yivi directly, instead of through
 * PubHubs Central and the global client.
 */
// Packages
import { defineStore } from 'pinia';

import { type StandaloneInfo } from '@hub-client/logic/core/standaloneLogin';

const useStandalone = defineStore('standalone', {
	state: () => ({
		// null for a hub entered through PubHubs Central
		info: null as StandaloneInfo | null,
	}),

	getters: {
		isStandalone: (state): boolean => state.info !== null,
		linkedHubs: (state) => state.info?.linked_hubs ?? [],
	},

	actions: {
		setInfo(info: StandaloneInfo | null) {
			this.info = info;
		},
	},
});

export { useStandalone };
