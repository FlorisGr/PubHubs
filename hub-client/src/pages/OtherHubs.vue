<template>
	<HeaderFooter>
		<template #header>
			<div
				class="flex h-full items-center"
				:class="isMobile ? 'pl-400' : 'pl-200'"
			>
				<div class="flex w-fit items-center gap-150 overflow-hidden">
					<Icon type="globe" />
					<H3 class="font-headings text-h3 text-on-surface font-semibold">
						{{ t('menu.other_hubs') }}
					</H3>
				</div>
			</div>
		</template>

		<div class="mx-auto my-500 flex w-full flex-col gap-200 px-400 md:w-4/6 md:px-0">
			<p>{{ t('others.other_hubs_explanation') }}</p>
			<LinkedHubList :hubs="standalone.linkedHubs" />
		</div>
	</HeaderFooter>
</template>

<script lang="ts" setup>
	// Packages
	import { computed } from 'vue';
	import { useI18n } from 'vue-i18n';

	// Components
	import H3 from '@hub-client/components/elements/H3.vue';
	import Icon from '@hub-client/components/elements/Icon.vue';
	import HeaderFooter from '@hub-client/components/ui/HeaderFooter.vue';
	import LinkedHubList from '@hub-client/components/ui/LinkedHubList.vue';

	// Stores
	import { useSettings } from '@hub-client/stores/settings';
	import { useStandalone } from '@hub-client/stores/standalone';

	const { t } = useI18n();
	const settings = useSettings();
	const standalone = useStandalone();

	const isMobile = computed(() => settings.isMobileState);
</script>
