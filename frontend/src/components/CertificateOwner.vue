<script setup>
defineProps({ certificate: { type: Object, required: true } })
</script>
<template><div class="certificate-owner"><strong>{{ certificate.owner_cn || certificate.organization || 'Владелец не указан' }}</strong><div v-if="certificate.department" class="small muted">{{ certificate.department }}</div><div v-if="certificate.organization && certificate.owner_cn && certificate.organization !== certificate.owner_cn" class="small muted">{{ certificate.organization }}</div></div></template>
