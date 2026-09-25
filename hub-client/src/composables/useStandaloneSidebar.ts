// Packages
import { computed } from 'vue';

// Stores
import { useSettings } from '@hub-client/stores/settings';
import { useStandalone } from '@hub-client/stores/standalone';

// A standalone hub client is the top-level page, so its own localStorage is not blocked
const COLLAPSED_KEY = 'pubhubs-standalone-sidebar-collapsed';

/**
 * Minimizing a standalone hub's rooms sidebar. A phone has no room for both the sidebar and the
 * page, so there it shows one of them next to the rail: the sidebar starts open (to pick a room)
 * and minimizes whenever the user navigates. Only the choice made on a larger screen is remembered.
 */
const useStandaloneSidebar = () => {
	const settings = useSettings();
	const standalone = useStandalone();

	// On a phone, the open sidebar takes the screen and the page is hidden
	const sidebarFillsScreen = computed(() => Boolean(settings.isMobileState) && standalone.isStandalone && !standalone.sidebarCollapsed);

	function restoreCollapsed() {
		if (settings.isMobileState) {
			standalone.setSidebarCollapsed(false);
			return;
		}
		try {
			standalone.setSidebarCollapsed(window.localStorage.getItem(COLLAPSED_KEY) === 'true');
		} catch {
			// Storage blocked; start expanded
		}
	}

	function setCollapsed(collapsed: boolean) {
		standalone.setSidebarCollapsed(collapsed);
		if (settings.isMobileState) return;
		try {
			window.localStorage.setItem(COLLAPSED_KEY, String(collapsed));
		} catch {
			// Only remembered for this visit then
		}
	}

	/**
	 * Called on navigation: on a phone, get the sidebar out of the way of the page navigated to.
	 */
	function collapseOnPhone() {
		if (settings.isMobileState) standalone.setSidebarCollapsed(true);
	}

	return { collapseOnPhone, restoreCollapsed, setCollapsed, sidebarFillsScreen };
};

export { useStandaloneSidebar };
