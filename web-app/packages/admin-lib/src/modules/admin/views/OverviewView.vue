<!--
Copyright (C) Lutra Consulting Limited

SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-MerginMaps-Commercial
-->

<template>
  <admin-layout>
    <app-container>
      <app-section ground>
        <template #header><h1 class="headline-h3">Overview</h1></template>
      </app-section>
    </app-container>

    <app-container>
      <div class="grid" v-if="usage">
        <usage-card class="col-12 sm:col-6 lg:col-3">
          <template #heading>Editors</template>
          <div
            class="w-full"
            :style="{
              height: '40px'
            }"
          >
            <PProgressBar :value="0" :show-value="false"></PProgressBar>
          </div>
          <template #title
            ><span>{{ usage?.editors }}</span></template
          >
        </usage-card>
        <usage-card class="col-12 sm:col-6 lg:col-3">
          <template #heading>Used storage</template>
          <div
            class="w-full"
            :style="{
              height: '40px'
            }"
          >
            <PProgressBar :value="0" :show-value="false"></PProgressBar>
          </div>
          <template #title
            ><span>{{
              $filters.filesize(usage.storage, null, 0)
            }}</span></template
          >
        </usage-card>
        <usage-card class="col-12 sm:col-6 lg:col-3">
          <template #heading>Registered accounts</template>
          <div
            class="w-full"
            :style="{
              height: '40px'
            }"
          >
            <PProgressBar :value="0" :show-value="false"></PProgressBar>
          </div>
          <template #title
            ><span>{{ usage?.users }}</span></template
          >
          <template #footer>
            <PButton
              severity="secondary"
              @click="$router.push({ name: AdminRoutes.ACCOUNTS })"
              class="w-full"
              label="Manage users"
            />
          </template>
        </usage-card>
        <usage-card class="col-12 sm:col-6 lg:col-3">
          <template #heading>Projects</template>
          <div
            class="w-full"
            :style="{
              height: '40px'
            }"
          >
            <PProgressBar :value="0" :show-value="false"></PProgressBar>
          </div>
          <template #title
            ><span>{{ usage?.projects }}</span></template
          >
          <template #footer>
            <PButton
              severity="secondary"
              @click="$router.push({ name: AdminRoutes.PROJECTS })"
              class="w-full"
              label="Manage projects"
            />
          </template>
        </usage-card>
        <usage-card v-if="showWorkspaces" class="col-12 sm:col-6 lg:col-3">
          <template #heading>Workspaces</template>
          <div
            class="w-full"
            :style="{
              height: '40px'
            }"
          >
            <PProgressBar :value="0" :show-value="false"></PProgressBar>
          </div>
          <template #title
            ><span>{{ usage?.workspaces }}</span></template
          >
          <template #footer>
            <PButton
              severity="secondary"
              @click="$router.push({ name: 'adminWorkspaces' })"
              class="w-full"
              label="Manage workspaces"
            />
          </template>
        </usage-card>
      </div>
    </app-container>
  </admin-layout>
</template>

<script lang="ts">
import { AppContainer, AppSection, UsageCard } from '@mergin/lib'
import { mapState } from 'pinia'
import { defineComponent } from 'vue'
import { useRouter } from 'vue-router'

import { AdminRoutes, useAdminStore } from '@/modules'
import { AdminLayout } from '@/modules/admin/components'

export default defineComponent({
  name: 'OverviewView',
  components: { AdminLayout, UsageCard, AppContainer, AppSection },
  computed: {
    AdminRoutes() {
      return AdminRoutes
    },
    ...mapState(useAdminStore, ['usage']),
    showWorkspaces() {
      const router = useRouter()
      return router.hasRoute('adminWorkspace') && this.usage?.workspaces
    }
  },
  methods: {
    getUsage(): void {
      const adminStore = useAdminStore()
      adminStore.getServerUsage()
    }
  },
  mounted() {
    this.getUsage()
  }
})
</script>

<style lang="scss" scoped>
.overview {
  margin-bottom: 30px;

  &-cards {
    min-height: 290px;
  }
}
</style>
