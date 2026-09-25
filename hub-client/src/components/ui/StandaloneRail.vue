<template>
	<!-- A standalone hub has no global bar, so the buttons used now and then live on this thin rail,
	     leaving the sidebar next to it for the rooms. -->
	<nav
		class="border-on-surface-disabled/25 flex h-full shrink-0 flex-col items-center justify-between gap-200 overflow-y-auto border-r-2 py-200"
		:class="isMobile ? 'w-[64px]' : 'w-[80px]'"
		:aria-label="t('menu.main_menu')"
	>
		<div class="flex flex-col items-center gap-200">
			<RailButton
				:to="{ name: 'home' }"
				:label="hubSettings.hubName ?? t('menu.home')"
			>
				<img
					v-if="!iconFailed"
					:src="hubSettings.iconUrlActiveTheme"
					alt=""
					class="h-[40px] w-[40px] rounded object-contain"
					@error="iconFailed = true"
				/>
				<Icon
					v-else
					type="house"
				/>
			</RailButton>

			<div class="bg-on-surface-disabled/25 h-[2px] w-600" />

			<RailButton
				v-for="item in railItems"
				:key="item.key"
				:to="item.to"
				:icon="item.icon"
				:label="t(item.key)"
			/>
			<RailButton
				v-if="isModerator"
				icon="circles-three-plus"
				:active="showModerationMenu && !standalone.sidebarCollapsed"
				:label="t('menu.moderation')"
				@click="openModerationMenu"
			/>
		</div>

		<div class="flex flex-col items-center gap-200">
			<RailButton
				icon="sidebar"
				:label="standalone.sidebarCollapsed ? t('menu.expand_sidebar') : t('menu.collapse_sidebar')"
				@click="setCollapsed(!standalone.sidebarCollapsed)"
			/>
			<RailButton
				icon="sliders-horizontal"
				:label="t('settings.title')"
				@click="emit('openPreferences')"
			/>
			<RailButton
				:label="t('settings.edit_profile')"
				@click="emit('openSettings')"
			>
				<Avatar
					:avatar-url="user.avatarUrl"
					:user-id="user.userId!"
				/>
			</RailButton>
			<RailButton
				icon="sign-out"
				:label="t('logout.logout')"
				@click="pubhubs.logout()"
			/>
		</div>
	</nav>
</template>

<script lang="ts" setup>
	// Packages
	import { computed, ref } from 'vue';
	import { useI18n } from 'vue-i18n';

	// Components
	import Icon from '@hub-client/components/elements/Icon.vue';
	import Avatar from '@hub-client/components/ui/Avatar.vue';
	import RailButton from '@hub-client/components/ui/RailButton.vue';

	// Composables
	import { useRoles } from '@hub-client/composables/roles.composable';
	import { useModerationMenu } from '@hub-client/composables/useModerationMenu';
	import { useStandaloneSidebar } from '@hub-client/composables/useStandaloneSidebar';

	// Stores
	import { useHubSettings } from '@hub-client/stores/hub-settings';
	import { useMenu } from '@hub-client/stores/menu';
	import { usePubhubsStore } from '@hub-client/stores/pubhubs';
	import { useSettings } from '@hub-client/stores/settings';
	import { useStandalone } from '@hub-client/stores/standalone';
	import { useUser } from '@hub-client/stores/user';

	const emit = defineEmits<{ openPreferences: []; openSettings: [] }>();

	// Home is the hub icon, and direct messages stay in the sidebar with the rooms
	const notOnRail = new Set(['home', 'direct-msg']);

	const { t } = useI18n();
	const hubSettings = useHubSettings();
	const menu = useMenu();
	const pubhubs = usePubhubsStore();
	const roles = useRoles();
	const settings = useSettings();
	const standalone = useStandalone();
	const user = useUser();
	const { showModerationMenu } = useModerationMenu();
	const { setCollapsed } = useStandaloneSidebar();

	const isMobile = computed(() => settings.isMobileState);
	const isModerator = computed(() => roles.userIsHubStewardOrHigher());
	const railItems = computed(() => menu.getMenu.filter((item) => !notOnRail.has((item.to as { name?: string }).name ?? '')));

	const iconFailed = ref(false);

	function openModerationMenu() {
		showModerationMenu.value = true;
		setCollapsed(false);
	}
</script>
