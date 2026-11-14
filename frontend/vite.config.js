import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// P08 target: one HTML, one CSS and one JS chunk embedded into the backend EXE.
export default defineConfig({
  plugins: [vue()],
  build: {
    // The backend serves a fixed bundle; keep the login background inside CSS.
    assetsInlineLimit: 512 * 1024,
    outDir: '../internal/backend/web/dist',
    emptyOutDir: true,
    cssCodeSplit: false,
    rollupOptions: {
      output: {
        manualChunks: undefined,
        entryFileNames: 'app.js',
        assetFileNames: 'app.[ext]'
      }
    }
  }
})
