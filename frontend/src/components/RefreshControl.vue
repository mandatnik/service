<script setup>
import { refreshSeconds } from '../autoRefresh'
</script>
<template>
  <label class="refresh-control"><span>Автообновление</span><select v-model.number="refreshSeconds" aria-label="Период автообновления таблиц"><option :value="0">Выключено</option><option :value="5">5 секунд</option><option :value="15">15 секунд</option><option :value="30">30 секунд</option><option :value="60">1 минута</option></select></label>
</template>
