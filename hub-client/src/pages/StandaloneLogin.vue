<template>
	<div class="bg-background text-on-surface flex min-h-screen w-full items-center justify-center p-400">
		<div class="bg-surface-base flex w-full max-w-md flex-col items-center gap-300 rounded-xl px-400 py-600 text-center shadow-lg">
			<H1 class="text-accent-primary">{{ hubName }}</H1>
			<p>{{ t('login.standalone_explanation') }}</p>
			<div
				:id="yiviElementId"
				class="w-[255px]"
			/>
			<template v-if="failed">
				<p class="text-accent-red-interactive">{{ t('login.standalone_failed') }}</p>
				<Button @click="startLogin">{{ t('login.login') }}</Button>
			</template>
			<template v-if="linkedHubs.length > 0">
				<H3 class="mt-300">{{ t('menu.other_hubs') }}</H3>
				<LinkedHubList :hubs="linkedHubs" />
			</template>
		</div>
	</div>
</template>

<script lang="ts" setup>
	// Packages
	import { onMounted, ref } from 'vue';
	import { useI18n } from 'vue-i18n';

	// Components
	import Button from '@hub-client/components/elements/Button.vue';
	import H1 from '@hub-client/components/elements/H1.vue';
	import H3 from '@hub-client/components/elements/H3.vue';
	import LinkedHubList from '@hub-client/components/ui/LinkedHubList.vue';

	// Logic
	import { type LinkedHub, yiviLogin } from '@hub-client/logic/core/standaloneLogin';
	import { createLogger } from '@hub-client/logic/logging/Logger';

	// Stores
	import { usePubhubsStore } from '@hub-client/stores/pubhubs';
	import { useSettings } from '@hub-client/stores/settings';

	withDefaults(defineProps<{ hubName?: string; linkedHubs?: LinkedHub[] }>(), { hubName: '', linkedHubs: () => [] });

	const emit = defineEmits<{ (e: 'logged-in'): void }>();

	const yiviElementId = 'standalone-yivi-login';
	const logger = createLogger('StandaloneLogin');
	const { t } = useI18n();
	const pubhubs = usePubhubsStore();
	const settings = useSettings();

	const failed = ref(false);

	onMounted(startLogin);

	async function startLogin() {
		failed.value = false;
		try {
			const result = await yiviLogin('#' + yiviElementId, settings.getActiveLanguage as 'nl' | 'en' | undefined);
			pubhubs.Auth.storeSoloAuth(result.access_token, result.mxid);
			emit('logged-in');
		} catch (error) {
			// Also reached when the user cancels in the Yivi app
			logger.info('Standalone Yivi login did not complete', { error });
			failed.value = true;
		}
	}
</script>
