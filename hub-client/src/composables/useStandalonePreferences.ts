// Stores
import { type Theme, type TimeFormat, useSettings } from '@hub-client/stores/settings';

// Types
type Preferences = {
	language?: string;
	theme?: Theme;
	timeformat?: TimeFormat;
};

// Normally the global client keeps these and sends them to the hub client. A standalone hub client
// is the top-level page, so its own localStorage is not blocked and it can keep them itself.
const PREFERENCES_KEY = 'pubhubs-standalone-preferences';

/**
 * Theme, language and time notation of a standalone hub, remembered across visits.
 */
const useStandalonePreferences = () => {
	const settings = useSettings();

	/**
	 * Apply the remembered preferences. Needs i18n initialised, since setLanguage only accepts
	 * available locales.
	 */
	function restorePreferences() {
		let preferences: Preferences;
		try {
			preferences = JSON.parse(window.localStorage.getItem(PREFERENCES_KEY) ?? '{}') as Preferences;
		} catch {
			// Storage blocked or garbled; keep the defaults
			return;
		}
		if (preferences.theme) settings.setTheme(preferences.theme);
		if (preferences.language) settings.setLanguage(preferences.language);
		if (preferences.timeformat) settings.setTimeFormat(preferences.timeformat);
	}

	/**
	 * Apply and remember new preferences.
	 */
	function savePreferences(preferences: Required<Preferences>) {
		settings.setTheme(preferences.theme);
		settings.setLanguage(preferences.language);
		settings.setTimeFormat(preferences.timeformat);
		try {
			window.localStorage.setItem(PREFERENCES_KEY, JSON.stringify(preferences));
		} catch {
			// Only applied for this visit then
		}
	}

	return { restorePreferences, savePreferences };
};

export { useStandalonePreferences };
