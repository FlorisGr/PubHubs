<template>
	<!-- What the global client's settings dialog offers, for a standalone hub that has no global
	     client. Leaves out notifications: running solo, the hub client shows none. -->
	<Dialog
		:buttons="buttonsSubmitCancel"
		:title="t('settings.title')"
	>
		<div class="flex flex-col gap-100">
			<div class="flex flex-col justify-between md:flex-row">
				<Label>{{ t('settings.theme') }}</Label>
				<ButtonGroup
					class="flex-wrap"
					:combined="true"
				>
					<Button
						v-for="option in settings.getThemeOptions(t)"
						:key="option.value"
						:variant="option.value === data.theme.value ? 'primary' : 'secondary'"
						size="sm"
						@click="updateData('theme', option.value)"
					>
						{{ option.label }}
					</Button>
				</ButtonGroup>
			</div>
			<div class="flex flex-col justify-between md:flex-row">
				<Label>{{ t('settings.language') }}</Label>
				<ButtonGroup
					class="flex-wrap"
					:combined="true"
				>
					<Button
						v-for="option in settings.getLanguageOptions ?? []"
						:key="option.value"
						:variant="option.value === data.language.value ? 'primary' : 'secondary'"
						size="sm"
						@click="updateData('language', option.value)"
					>
						{{ option.label }}
					</Button>
				</ButtonGroup>
			</div>
			<div class="flex flex-col justify-between md:flex-row">
				<Label>{{ t('settings.timeformat') }}</Label>
				<ButtonGroup
					class="flex-wrap"
					:combined="true"
				>
					<Button
						v-for="option in settings.getTimeFormatOptions(t)"
						:key="option.value"
						:variant="option.value === data.timeformat.value ? 'primary' : 'secondary'"
						size="sm"
						@click="updateData('timeformat', option.value)"
					>
						{{ option.label }}
					</Button>
				</ButtonGroup>
			</div>
		</div>
	</Dialog>
</template>

<script lang="ts" setup>
	// Packages
	import { onMounted } from 'vue';
	import { useI18n } from 'vue-i18n';

	// Components
	import Button from '@hub-client/components/elements/Button.vue';
	import ButtonGroup from '@hub-client/components/elements/ButtonGroup.vue';
	import Label from '@hub-client/components/forms/elements/Label.vue';
	import Dialog from '@hub-client/components/ui/Dialog.vue';

	// Composables
	import { type FormDataType, useFormState } from '@hub-client/composables/useFormState';
	import { useStandalonePreferences } from '@hub-client/composables/useStandalonePreferences';

	// Stores
	import { DialogOk, buttonsSubmitCancel, useDialog } from '@hub-client/stores/dialog';
	import { type Theme, type TimeFormat, useSettings } from '@hub-client/stores/settings';

	const { t } = useI18n();
	const { data, setSubmitButton, setData, updateData } = useFormState();
	const dialog = useDialog();
	const settings = useSettings();
	const { savePreferences } = useStandalonePreferences();

	setData({
		theme: { value: settings.getSetTheme as FormDataType },
		language: { value: settings.getActiveLanguage as FormDataType },
		timeformat: { value: settings.getTimeFormat as FormDataType },
	});

	onMounted(() => {
		dialog.addCallback(DialogOk, () => {
			savePreferences({
				language: data.language.value as string,
				theme: data.theme.value as Theme,
				timeformat: data.timeformat.value as TimeFormat,
			});
		});
		setSubmitButton(dialog.properties.buttons[0]);
	});
</script>
