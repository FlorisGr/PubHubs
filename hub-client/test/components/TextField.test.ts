// Packages
import { createTestingPinia } from '@pinia/testing';
import { mount } from '@vue/test-utils';
import { describe, expect, test } from 'vitest';
import { createI18n } from 'vue-i18n';

// Components
import TextField from '@hub-client/components/forms/elements/TextField.vue';

import { en } from '@hub-client/locales/en';

const i18n = createI18n({ legacy: false, locale: 'en', messages: { en } });

const mountTextField = (label: string) =>
	mount(TextField, {
		props: { validation: { required: true } },
		slots: label ? { default: label } : {},
		global: { plugins: [i18n, createTestingPinia()], provide: { addField: () => {}, removeField: () => {} } },
	});

describe('TextField.vue', () => {
	// ValidateField's default slot is scoped (it hands the field its id), so it can't be called for a
	// label without its props. That used to throw once a field without a label or name mounted, e.g.
	// the onboarding page's name field when the window resized into its mobile layout.
	test('mounts without a label or name', () => {
		expect(() => mountTextField('')).not.toThrow();
	});

	test('uses its label as field name', () => {
		const wrapper = mountTextField('display name');
		expect(wrapper.find('input').attributes('name')).toBe('Display name');
	});
});
