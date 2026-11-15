<script setup>
import { computed } from 'vue'
import { certificateParty } from '../certificates'
const props = defineProps({ certificate: { type: Object, required: true }, issuer: Boolean })
const party = computed(() => certificateParty(props.certificate, props.issuer))
</script>
<template>
  <div class="certificate-party">
    <strong class="certificate-party-name">{{ party.primary }}</strong>
    <div v-if="party.subtitle" class="small muted certificate-party-subtitle" :title="party.subtitle">{{ party.subtitle }}</div>
    <div v-if="party.badges.length" class="certificate-party-badges">
      <template v-for="badge in party.badges" :key="badge.label">
        <a v-if="badge.href" class="badge badge-neutral" :href="badge.href" @click.stop @keydown.stop>{{ badge.label }}: {{ badge.value }}</a>
        <span v-else class="badge badge-neutral">{{ badge.label }}: {{ badge.value }}</span>
      </template>
    </div>
  </div>
</template>
