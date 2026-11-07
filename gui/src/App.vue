<template>
  <el-container class="app">
    <el-header class="header">
      <div class="brand">
        <img class="logo" :src="logoSrc" alt="Rocket Client" />
        <div>
          <div class="title">Rocket Client</div>
          <div class="subtitle">SSL VPN 客户端</div>
        </div>
      </div>
      <div class="header-right">
        <el-tag v-if="connected" type="success" effect="dark" round>
          <span class="dot" /> 已连接
        </el-tag>
        <el-tag v-else-if="connecting" type="warning" effect="dark" round>连接中…</el-tag>
        <el-tag v-else type="info" effect="plain" round>未连接</el-tag>
        <span v-if="connected" class="uptime mono">{{ uptime }}</span>
      </div>
    </el-header>

    <el-main class="main">
      <div class="grid">
        <!-- 左：配置 -->
        <div class="col-left">
          <el-card shadow="never" class="card">
            <template #header>
              <div class="card-head">
                <el-icon><Link /></el-icon>
                <span>连接配置</span>
              </div>
            </template>

            <el-form label-position="top" size="default" :disabled="connected || connecting">
              <el-form-item label="网关地址">
                <el-select
                  v-model="config.gateway"
                  class="w100"
                  filterable
                  allow-create
                  default-first-option
                  clearable
                  placeholder="选择历史网关，或直接输入 IP:端口"
                >
                  <el-option v-for="g in gateways" :key="g" :label="g" :value="g">
                    <span class="mono">{{ g }}</span>
                    <el-icon class="opt-icon" @click.stop="forgetGateway(g)"><Close /></el-icon>
                  </el-option>
                </el-select>
              </el-form-item>

              <el-form-item label="账号">
                <el-input v-model="config.username" placeholder="VPN 登录账号">
                  <template #prefix><el-icon><User /></el-icon></template>
                </el-input>
              </el-form-item>

              <el-form-item label="密码">
                <el-input
                  v-model="config.password"
                  type="password"
                  show-password
                  placeholder="VPN 登录密码"
                  @keyup.enter="connect"
                >
                  <template #prefix><el-icon><Lock /></el-icon></template>
                </el-input>
              </el-form-item>

              <el-form-item>
                <template #label>
                  <span class="lbl">客户端 MAC</span>
                  <el-tooltip
                    content="留空则自动读取本机网卡；多人共用同一账号时建议各自填写本机 MAC"
                    placement="top"
                  >
                    <el-icon class="lbl-tip"><QuestionFilled /></el-icon>
                  </el-tooltip>
                </template>
                <el-input v-model="config.mac" placeholder="留空自动获取本机 MAC" class="mono">
                  <template #prefix><el-icon><Monitor /></el-icon></template>
                  <template #append>
                    <el-button :icon="Refresh" @click="fillLocalMac" title="读取本机 MAC" />
                  </template>
                </el-input>
              </el-form-item>

              <el-form-item label="走 VPN 的网段">
                <div class="routes">
                  <el-tag
                    v-for="(r, i) in config.routes"
                    :key="r"
                    closable
                    type="primary"
                    effect="plain"
                    @close="removeRoute(i)"
                  >
                    {{ r }}
                  </el-tag>
                  <el-input
                    v-model="newRoute"
                    size="small"
                    class="route-input"
                    placeholder="192.168.20.0/24"
                    @keyup.enter="addRoute"
                  />
                  <el-button size="small" :icon="Plus" @click="addRoute">添加</el-button>
                </div>
                <div class="hint">只有这些网段走 VPN，本地网络与公网完全不受影响</div>
              </el-form-item>

              <el-form-item>
                <el-checkbox v-model="config.insecure">跳过证书校验（自签名网关需要）</el-checkbox>
              </el-form-item>
            </el-form>

            <div class="actions">
              <el-button
                v-if="!connected"
                type="primary"
                size="large"
                :loading="connecting"
                class="flex1"
                @click="connect"
              >
                {{ connecting ? '连接中…' : '连接 VPN' }}
              </el-button>
              <el-button v-else type="danger" size="large" plain class="flex1" @click="disconnect">
                断开连接
              </el-button>
            </div>
          </el-card>
        </div>

        <!-- 右：状态 + 日志 -->
        <div class="col-right">
          <el-card shadow="never" class="card state-card">
            <template #header>
              <div class="card-head">
                <el-icon><Odometer /></el-icon>
                <span>连接状态</span>
              </div>
            </template>
            <el-descriptions :column="2" size="small" border>
              <el-descriptions-item label="虚拟 IP">
                <span class="mono">{{ vip || '—' }}</span>
              </el-descriptions-item>
              <el-descriptions-item label="隧道">
                <span class="mono">{{ connected ? 'TLS / TCP' : '—' }}</span>
              </el-descriptions-item>
              <el-descriptions-item label="生效网段" :span="2">
                <template v-if="activeRoutes.length">
                  <el-tag
                    v-for="r in activeRoutes"
                    :key="r"
                    size="small"
                    type="success"
                    effect="plain"
                    class="mr4"
                  >{{ r }}</el-tag>
                </template>
                <span v-else class="muted">—</span>
              </el-descriptions-item>
              <el-descriptions-item label="本地网络" :span="2">
                <span class="ok-text">不受影响（默认路由未改动）</span>
              </el-descriptions-item>
            </el-descriptions>
          </el-card>

          <el-card shadow="never" class="card log-card">
            <template #header>
              <div class="card-head space-between">
                <div class="card-head">
                  <el-icon><Document /></el-icon>
                  <span>运行日志</span>
                </div>
                <el-button link size="small" @click="logs = []">清空</el-button>
              </div>
            </template>
            <el-scrollbar ref="scrollRef" class="log-box">
              <div v-if="!logs.length" class="log-empty">暂无日志</div>
              <div
                v-for="(l, i) in logs"
                :key="i"
                class="log-line mono"
                :class="'log-' + l.level"
              >
                <span class="log-time">{{ l.time }}</span>{{ l.msg }}
              </div>
            </el-scrollbar>
          </el-card>
        </div>
      </div>
    </el-main>
  </el-container>
</template>

<script setup>
import { ref, reactive, nextTick, onMounted, onUnmounted } from 'vue'
import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import { ElMessage } from 'element-plus'
import { Plus, Refresh, Close, QuestionFilled } from '@element-plus/icons-vue'
import logoSrc from './assets/gateway.svg'

// 只预置网段，其余留空 —— 分发时不携带任何账号信息
const DEFAULTS = {
  gateway: '',
  username: '',
  password: '',
  mac: '',
  routes: ['10.0.0.0/8', '172.16.0.0/12', '192.0.2.0/24'],
  insecure: true
}

const CFG_KEY = 'rocket-config'
const GW_KEY = 'rocket-gateways'

function readJSON(key, fallback) {
  try {
    const v = JSON.parse(localStorage.getItem(key) || 'null')
    return v ?? fallback
  } catch {
    return fallback
  }
}

const saved = readJSON(CFG_KEY, null)
const config = reactive({ ...DEFAULTS, ...(saved || {}) })
if (!Array.isArray(config.routes) || !config.routes.length) config.routes = [...DEFAULTS.routes]

// 连接过的网关地址（最新的在最前）
const gateways = ref(Array.isArray(readJSON(GW_KEY, [])) ? readJSON(GW_KEY, []) : [])

const newRoute = ref('')
const connecting = ref(false)
const connected = ref(false)
const vip = ref('')
const activeRoutes = ref([])
const logs = ref([])
const scrollRef = ref(null)
const uptime = ref('00:00:00')

let tick = null
let startedAt = 0
let unlisteners = []

const logLevel = (msg) => {
  const s = String(msg)
  if (/fail|error|reject|cannot|失败|错误/i.test(s)) return 'error'
  if (/ok|success|ready|active|成功|通过|完成/i.test(s)) return 'ok'
  return 'info'
}

function scrollToEnd() {
  nextTick(() => scrollRef.value?.setScrollTop(1e9))
}

function addLog(msg, level) {
  logs.value.push({
    time: new Date().toLocaleTimeString('zh-CN', { hour12: false }),
    msg: String(msg),
    level: level || logLevel(msg)
  })
  if (logs.value.length > 800) logs.value.shift()
  scrollToEnd()
}

function rememberGateway(gw) {
  const v = String(gw || '').trim()
  if (!v) return
  const list = gateways.value.filter((g) => g !== v)
  list.unshift(v)
  gateways.value = list.slice(0, 8)
  localStorage.setItem(GW_KEY, JSON.stringify(gateways.value))
}

function forgetGateway(gw) {
  gateways.value = gateways.value.filter((g) => g !== gw)
  localStorage.setItem(GW_KEY, JSON.stringify(gateways.value))
}

async function fillLocalMac(silent) {
  try {
    const m = await invoke('local_mac')
    if (m) {
      config.mac = m
      if (!silent) ElMessage.success(`已读取本机 MAC：${m}`)
    } else if (!silent) {
      ElMessage.warning('未能自动读取，请手动填写（getmac /v 可查）')
    }
  } catch (e) {
    if (!silent) ElMessage.warning(String(e))
  }
}

function addRoute() {
  const v = newRoute.value.trim()
  if (!v) return
  if (!/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(v)) {
    ElMessage.warning('格式应为 CIDR，例如 192.168.20.0/24')
    return
  }
  if (config.routes.includes(v)) {
    ElMessage.warning('该网段已存在')
    return
  }
  config.routes.push(v)
  newRoute.value = ''
}

function removeRoute(i) {
  config.routes.splice(i, 1)
}

function formatDuration(ms) {
  const s = Math.floor(ms / 1000)
  const p = (n) => String(n).padStart(2, '0')
  return `${p(Math.floor(s / 3600))}:${p(Math.floor((s % 3600) / 60))}:${p(s % 60)}`
}

async function connect() {
  if (!config.gateway || !config.username || !config.password) {
    ElMessage.warning('请填写网关地址、账号和密码')
    return
  }
  if (!config.routes.length) {
    ElMessage.warning('至少需要一个走 VPN 的网段')
    return
  }
  localStorage.setItem(CFG_KEY, JSON.stringify(config))

  connecting.value = true
  logs.value = []
  try {
    const res = await invoke('vpn_connect', {
      config: {
        gateway: config.gateway.trim(),
        username: config.username,
        password: config.password,
        mac: (config.mac || '').trim(),
        insecure: config.insecure,
        routes: [...config.routes]
      }
    })
    connected.value = true
    vip.value = res.vip || ''
    activeRoutes.value = res.routes || []
    rememberGateway(config.gateway)
    if (!config.mac) fillLocalMac(true)
    startedAt = Date.now()
    uptime.value = '00:00:00'
    tick = setInterval(() => {
      uptime.value = formatDuration(Date.now() - startedAt)
    }, 1000)
    addLog(`连接成功，虚拟 IP ${res.vip}`, 'ok')
  } catch (e) {
    addLog(e, 'error')
    ElMessage.error(String(e))
  } finally {
    connecting.value = false
  }
}

async function disconnect() {
  try {
    await invoke('vpn_disconnect')
  } catch (e) {
    addLog(e, 'error')
  }
  connected.value = false
  connecting.value = false
  vip.value = ''
  activeRoutes.value = []
  if (tick) clearInterval(tick)
  tick = null
  uptime.value = '00:00:00'
  addLog('已断开连接', 'info')
}

onMounted(async () => {
  unlisteners.push(await listen('vpn-log', (e) => addLog(e.payload)))
  unlisteners.push(
    await listen('vpn-state', (e) => {
      const s = e.payload
      if (s && s.connected === false) {
        connected.value = false
        vip.value = ''
        activeRoutes.value = []
        if (tick) clearInterval(tick)
        tick = null
      }
    })
  )
  if (!config.mac) fillLocalMac(true)
  addLog('就绪。填写配置后点击「连接 VPN」。', 'info')
})

onUnmounted(() => {
  unlisteners.forEach((u) => u())
  if (tick) clearInterval(tick)
})
</script>

<style scoped>
.app {
  height: 100vh;
}

.header {
  height: 60px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: #fff;
  border-bottom: 1px solid #e4e7ed;
  padding: 0 20px;
}

.brand {
  display: flex;
  align-items: center;
  gap: 12px;
}

.logo {
  width: 34px;
  height: 34px;
  display: block;
  object-fit: contain;
  user-select: none;
  -webkit-user-drag: none;
}

.title {
  font-size: 15px;
  font-weight: 600;
  line-height: 1.2;
}

.subtitle {
  font-size: 11px;
  color: #909399;
  line-height: 1.4;
}

.header-right {
  display: flex;
  align-items: center;
  gap: 12px;
}

.uptime {
  color: #606266;
}

.dot {
  display: inline-block;
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: #fff;
  margin-right: 5px;
  vertical-align: middle;
}

.main {
  padding: 16px;
  overflow: hidden;
}

.grid {
  display: grid;
  grid-template-columns: 400px 1fr;
  gap: 16px;
  height: 100%;
}

.col-left,
.col-right {
  display: flex;
  flex-direction: column;
  gap: 16px;
  min-height: 0;
}

.card {
  border-radius: 10px;
  border: 1px solid #e4e7ed;
}

.card :deep(.el-card__header) {
  padding: 12px 16px;
  border-bottom: 1px solid #f0f2f5;
}

.card :deep(.el-card__body) {
  padding: 16px;
}

.card-head {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 13px;
  font-weight: 500;
  color: #303133;
}

.space-between {
  justify-content: space-between;
}

.w100 {
  width: 100%;
}

.lbl-tip {
  margin-left: 4px;
  color: #c0c4cc;
  cursor: help;
  vertical-align: -2px;
}

.opt-icon {
  float: right;
  margin-top: 8px;
  color: #c0c4cc;
}

.opt-icon:hover {
  color: #f56c6c;
}

.routes {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  align-items: center;
  width: 100%;
}

.route-input {
  width: 130px;
}

.hint {
  font-size: 11px;
  color: #a8abb2;
  margin-top: 6px;
  line-height: 1.5;
  width: 100%;
}

.actions {
  display: flex;
  gap: 10px;
  margin-top: 4px;
}

.flex1 {
  flex: 1;
}

.state-card :deep(.el-descriptions__label) {
  width: 88px;
  color: #909399;
  font-weight: 400;
}

.log-card {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-height: 0;
}

.log-card :deep(.el-card__body) {
  flex: 1;
  min-height: 0;
  padding: 0;
}

.log-box {
  height: 100%;
  background: #1e1f22;
  padding: 10px 14px;
}

.log-box :deep(.el-scrollbar__wrap) {
  overflow-x: hidden;
}

.log-empty {
  color: #5c5f66;
  font-size: 12px;
  padding: 4px 0;
}

.log-line {
  color: #d4d7de;
  font-size: 12px;
  line-height: 1.7;
  word-break: break-all;
}

.log-time {
  color: #6b7280;
  margin-right: 8px;
}

.log-info {
  color: #a8b0bf;
}

.log-ok {
  color: #67c23a;
}

.log-error {
  color: #f56c6c;
}

.mr4 {
  margin-right: 4px;
}

.muted {
  color: #c0c4cc;
}

.ok-text {
  color: #67c23a;
}
</style>
