// Packages
import { computed, getCurrentInstance, ref, useSlots } from 'vue';

// Logic
import { firstToUpper } from '@hub-client/logic/core/extensions';

/**
 * @param props
 * @param model
 * @param options.nameFromSlot Whether the default slot is the field's label, to use as its name. Not
 *   for a component whose default slot is scoped, since that can't be called without its props.
 */
export function useFormInput(
	props: { id?: string; name?: string; [key: string]: unknown },
	model: { value: unknown } | undefined = undefined,
	{ nameFromSlot = true }: { nameFromSlot?: boolean } = {},
) {
	// In setup: the computed below can be evaluated later, when there is no current instance
	const slots = useSlots();
	const changed = ref(false);
	const hasFocus = ref(false);

	const id = computed(() => {
		if (props.id) return props.id;
		return 'id-' + getCurrentInstance()?.uid;
	});

	const slotDefault = computed(() => {
		if (!nameFromSlot || !slots.default) return '';
		return slots.default()[0]?.children?.toString() ?? '';
	});

	// Set fieldname explicitly in props, or if not set explicitly, it will use the 'label' inside the default slot as fieldname
	const fieldName = computed(() => {
		let name = '';
		if (props.name) {
			name = props.name;
		} else {
			name = slotDefault.value;
		}
		return firstToUpper(name);
	});

	const setFocus = (state: boolean) => {
		hasFocus.value = state;
	};

	const update = () => {
		changed.value = true;
	};

	// For radio inputs
	const select = (value: string | number | boolean) => {
		if (model) {
			if (model.value === value) {
				model.value = null;
			} else {
				model.value = value;
			}
			changed.value = true;
		}
	};

	// For checkbox and toggle inputs
	const toggle = (disabled: boolean = false) => {
		if (!disabled && model) {
			model.value = !model.value;
			changed.value = true;
		}
	};

	return { id, slotDefault, fieldName, setFocus, hasFocus, update, select, toggle, changed };
}
