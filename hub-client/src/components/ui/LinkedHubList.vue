<template>
	<ul class="flex w-full flex-col gap-200">
		<li
			v-for="hub in hubs"
			:key="hub.url"
		>
			<!-- Every hub has its own login, so leave this one instead of embedding the other -->
			<a
				:href="hub.url"
				rel="noopener noreferrer"
				class="bg-surface-sunken hover:bg-surface-elevated rounded-base flex items-center gap-200 px-300 py-200 text-left transition-colors"
			>
				<Icon type="link" />
				<div class="flex min-w-0 flex-col">
					<span class="truncate font-semibold">{{ hub.name }}</span>
					<span
						v-if="hub.description"
						class="text-on-surface-dim text-label-small"
						>{{ hub.description }}</span
					>
				</div>
			</a>
		</li>
	</ul>
</template>

<script lang="ts" setup>
	// Components
	import Icon from '@hub-client/components/elements/Icon.vue';

	// Logic
	import { type LinkedHub } from '@hub-client/logic/core/standaloneLogin';

	withDefaults(defineProps<{ hubs?: LinkedHub[] }>(), { hubs: () => [] });
</script>
