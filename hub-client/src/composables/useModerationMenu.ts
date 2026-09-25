// Packages
import { ref } from 'vue';

// When adding a page to the moderation sidebar, add its route here
const moderationRoutes = new Set(['hub-settings', 'manage-rooms', 'manage-users', 'manage-roles', 'reports', 'editroom']);

// Module-level, so the standalone rail can open the moderation menu that the hub sidebar renders
const showModerationMenu = ref(false);

/**
 * Whether the hub sidebar shows the moderation menu instead of the rooms.
 */
const useModerationMenu = () => ({ moderationRoutes, showModerationMenu });

export { useModerationMenu };
