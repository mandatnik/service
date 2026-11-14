<script setup>
import { computed, ref } from 'vue'
const props = defineProps({ items: Array, modelValue: Array, label: String })
const emit = defineEmits(['update:modelValue'])
const search = ref('')
const visible = computed(() => props.items.filter(item => item.name.toLocaleLowerCase().includes(search.value.toLocaleLowerCase())))
function change(id, checked) { emit('update:modelValue', checked ? [...props.modelValue, id] : props.modelValue.filter(value => value !== id)) }
</script>
<template><fieldset class="assignment-picker"><legend>{{ label }} · {{ modelValue.length }}</legend><input v-model="search" :placeholder="`Найти: ${label.toLowerCase()}`" :aria-label="`Поиск: ${label}`" /><div class="assignment-options"><label v-for="item in visible" :key="item.id" class="checkbox-field"><input type="checkbox" :checked="modelValue.includes(item.id)" @change="change(item.id, $event.target.checked)" />{{ item.name }}</label><div v-if="!visible.length" class="small muted">Ничего не найдено</div></div></fieldset></template>
