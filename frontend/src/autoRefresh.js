import { ref, onMounted, onUnmounted, watch } from 'vue'

const periods = [0, 5, 15, 30, 60]
let saved = 15
try { const value = localStorage.getItem('admin-refresh-seconds'); if (value !== null && periods.includes(Number(value))) saved = Number(value) } catch {}
export const refreshSeconds = ref(saved)
watch(refreshSeconds, value => { try { localStorage.setItem('admin-refresh-seconds', String(value)) } catch {} })

// Schedule after completion, so slow requests cannot overlap or pile up.
export function useAutoRefresh(load, blocked = () => false) {
  let timer, stopped = false
  function schedule() {
    clearTimeout(timer)
    if (!stopped && refreshSeconds.value) timer = setTimeout(tick, refreshSeconds.value * 1000)
  }
  async function tick() {
    try {
      const editing = document.activeElement?.closest('input, textarea, [contenteditable="true"], dialog')
      if (!document.hidden && !editing && !document.querySelector('dialog[open]') && !blocked()) await load()
    } catch { /* A later refresh retries; view loaders display request failures. */ } finally { schedule() }
  }
  const stopWatch = watch(refreshSeconds, schedule)
  onMounted(schedule)
  onUnmounted(() => { stopped = true; clearTimeout(timer); stopWatch() })
}
