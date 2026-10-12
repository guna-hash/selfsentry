import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
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
