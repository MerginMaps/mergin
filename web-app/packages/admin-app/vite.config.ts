import { NodeGlobalsPolyfillPlugin } from '@esbuild-plugins/node-globals-polyfill'
// import { NodeModulesPolyfillPlugin } from '@esbuild-plugins/node-modules-polyfill'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'path'
import { defineConfig } from 'vite'
import vuetify from 'vite-plugin-vuetify'

const serverPort = process.env.FLASK_RUN_PORT ?? 5000

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => ({
  plugins: [vue(), vuetify()],

  resolve: {
    alias: {
      '@': resolve(__dirname, './src'),
      'vue-i18n': 'vue-i18n/dist/vue-i18n.cjs.js',
      // buffer: 'buffer/',
      events: 'events',
      https: 'agent-base',
      // http: 'stream-http',
      // https: 'https-browserify',
      path: 'path-browserify',
      url: 'url/'
    }
  },
  build: {
    sourcemap: mode !== 'production',
    rollupOptions: {
      // make sure to externalize deps that shouldn't be bundled
      // into your library
      external: ['vue'],
      output: {
        exports: 'named',
        // Provide global variables to use in the UMD build
        // for externalized deps
        globals: {
          vue: 'Vue'
        }
      }
    }
  },
  optimizeDeps: {
    exclude: ['vue', '@mergin'],
    esbuildOptions: {
      define: {
        global: 'globalThis'
      },
      plugins: [
        NodeGlobalsPolyfillPlugin({
          process: true,
          buffer: true
        })
        // NodeModulesPolyfillPlugin()
      ]
    }
    // include: ['linked-dep', 'node_modules']
  },
  server: {
    proxy: {
      '/v1': {
        target: `http://127.0.0.1:${serverPort}`
      },
      '/app': {
        target: `http://127.0.0.1:${serverPort}`
      },
      '/ping': {
        target: `http://127.0.0.1:${serverPort}`
      },
      '/config': {
        target: `http://127.0.0.1:${serverPort}`
      }
    },
    watch: {
      ignored: ['!**/node_modules/@mergin/**']
    }
  }
}))