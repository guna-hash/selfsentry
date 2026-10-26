import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  // DOM integration workers compete for CPU/RAM on the supported small VMs.
  // Preserve file isolation and the existing test deadlines, but bound concurrency.
  test: { maxWorkers: 2 },
  build: {
    rolldownOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes('/node_modules/')) return
          if (id.includes('/recharts/')) return 'charts'
          if (/\/(framer-motion|motion-dom|motion-utils)\//.test(id))
            return 'motion'
          if (/\/(react|react-dom|react-router|react-router-dom|scheduler)\//.test(id))
            return 'vendor'
        },
      },
    },
  },
})
