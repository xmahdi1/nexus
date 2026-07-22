import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import router from './router'
import { i18n } from './lib/i18n'
import { applyTheme, getTheme } from './lib/theme'
import './styles.css'

applyTheme(getTheme())

const app = createApp(App)
app.use(createPinia())
app.use(router)
app.use(i18n)
app.mount('#app')