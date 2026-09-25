<template>
	<component
		:is="to ? RouterLink : 'button'"
		v-bind="to ? { to, activeClass: '', exactActiveClass: '' } : { type: 'button' }"
		class="focus-visible:ring-accent-blue-interactive flex items-center justify-center rounded-md p-150 transition-colors outline-none hover:cursor-pointer focus-visible:ring-3"
		:class="isActive ? 'bg-surface-elevated text-accent-primary' : 'text-on-surface hover:bg-surface-elevated'"
		:aria-label="label"
		:aria-current="isActive && to ? 'page' : undefined"
		:title="label"
	>
		<slot>
			<Icon :type="icon" />
		</slot>
	</component>
</template>

<script lang="ts" setup>
	// Packages
	import { computed } from 'vue';
	import { type RouteLocationRaw, RouterLink, useRoute, useRouter } from 'vue-router';

	// Components
	import Icon from '@hub-client/components/elements/Icon.vue';

	const props = withDefaults(defineProps<{ active?: boolean; icon?: string; label: string; to?: RouteLocationRaw }>(), {
		active: false,
		icon: '',
		to: undefined,
	});

	const route = useRoute();
	const router = useRouter();

	const isActive = computed(() => props.active || (props.to !== undefined && router.resolve(props.to).name === route.name));
</script>
