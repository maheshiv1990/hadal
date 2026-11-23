import { defineConfig } from 'vite'
import solid from 'vite-plugin-solid'

export default defineConfig({
  plugins: [solid()],
  server: {
    // In local dev, forward API calls to the backend (cargo run).
    proxy: {
      '/api': 'http://localhost:8080',
    },
  },
})
