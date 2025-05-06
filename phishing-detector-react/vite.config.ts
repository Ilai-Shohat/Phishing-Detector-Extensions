import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist',
    sourcemap: true,
    rollupOptions: {
      input: {
        // Align entry names with manifest references
        popup: 'index.html',
        background: 'src/background.ts',
        'content-script': 'src/content-script.ts'
      },
      output: {
        entryFileNames: '[name].js'
      }
    }
  }
});