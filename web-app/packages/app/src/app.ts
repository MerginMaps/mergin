// Copyright (C) Lutra Consulting Limited
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-MerginMaps-Commercial

// styles must be imported first (at least before imports of our libs)
import 'material-icons/iconfont/material-icons.scss'
import '@fortawesome/fontawesome-free/css/all.css'
import '@mdi/font/css/materialdesignicons.css'
import PrimeVue from 'primevue/config';
import "primevue/resources/primevue.min.css";
import "primeflex/primeflex.min.css"
import "@mergin/lib/dist/sass/themes/mm-theme-light/theme.scss"
import "@tabler/icons-webfont/tabler-icons.min.css"

import '@mergin/lib/dist/style.css'

import {
  dateUtils,
  textUtils,
  numberUtils,
  getHttpService,
  MerginComponentUuidMixin
} from '@mergin/lib'
import PortalVue from 'portal-vue'
import { createApp } from 'vue'
import { createMetaManager } from 'vue-meta'

import App from './App.vue'
import { createRouter } from './router'
import { addRouterToPinia, getPiniaInstance } from './store'

import i18n from '@/plugins/i18n/i18n'
import vuetify from '@/plugins/vuetify/vuetify'
import Tooltip from 'primevue/tooltip';

const createMerginApp = () => {
  const pinia = getPiniaInstance()
  const router = createRouter(pinia)
  addRouterToPinia(router)

  const app = createApp(App)
    .mixin(MerginComponentUuidMixin)
    .use(pinia)
    .use(router)
    .use(vuetify)
    .use(i18n)
    .use(PortalVue)
    .use(createMetaManager())
    .use(PrimeVue)
    .directive('tooltip', Tooltip)

  app.config.globalProperties.$http = getHttpService()
  app.config.globalProperties.$filters = {
    filesize: (value, unit, digits = 2, minUnit: numberUtils.SizeUnit = 'B') =>
      numberUtils.formatFileSize(value, unit, digits, minUnit),
    datetime: dateUtils.formatDateTime,
    date: dateUtils.formatDate,
    timediff: dateUtils.formatTimeDiff,
    remainingtime: dateUtils.formatRemainingTime,
    totitle: textUtils.formatToTitle,
    currency: numberUtils.formatToCurrency
  }

  return app
}
export { createMerginApp }