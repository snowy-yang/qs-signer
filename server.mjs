#!/usr/bin/env node
// 汽水音乐外部签名服务 —— 在 Linux 上用 Wine 跑官方 bdms.node，对外只提供签名
//
// 为什么需要它：bdms.node 是 Windows PE 原生模块，只能由 Windows 版 Node/Electron 加载。
// 把「加载官方模块」这件事单独关进一个容器（Wine + Windows Node），主服务就能跑在任何平台，
// 通过 HTTP 拿 X-Helios / X-Medusa —— 契约与 sodahub-org/libmssdk、libresoda、
// Meting-API 的远程签名服务互通（三者 JSON 可互换）。
//
// 路由：
//   GET  /healthz      → { ok, service, version, bdmsAvailable, deviceId(脱敏), auth, platform }
//   GET  /config       → 需鉴权：设备身份（调用方据此对齐 URL 里的 device_id/iid）
//   POST /sign         → { url, method?, headers, body?, device_id? } → { ok, headers:{X-Helios,X-Medusa}, device_id, elapsed_ms }
//   POST /selftest     → 用样例请求自检（不联网）
//
// 鉴权：QS_SIGNER_TOKEN（Authorization: Bearer <token>）。未设 token 时除非
//   QS_SIGNER_ALLOW_ANONYMOUS=1，否则拒绝启动 —— 签名能力等价于账号取流能力，别裸奔。
// 环境变量：QS_SIGNER_BIND(127.0.0.1) / QS_SIGNER_PORT(8899) / QS_SIGNER_TOKEN /
//   QS_SIGNER_DEVICE_ID / QS_SIGNER_BDMS_MODULE(默认 ./vendor/bdms.node) / QS_SIGNER_MAX_BODY
// 日志只记请求形状与耗时：Cookie、X-Helios、X-Medusa 一律不落盘。
import { createRequire } from 'node:module'
import http from 'node:http'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const require = createRequire(import.meta.url)
const __dirname = path.dirname(fileURLToPath(import.meta.url))

const VERSION = '0.1.0'
const SERVICE = 'qs-signer'
const BIND = process.env.QS_SIGNER_BIND || '127.0.0.1'
const PORT = Number(process.env.QS_SIGNER_PORT) || 8899
const TOKEN = process.env.QS_SIGNER_TOKEN || ''
const ALLOW_ANONYMOUS = process.env.QS_SIGNER_ALLOW_ANONYMOUS === '1'
const DEFAULT_DEVICE_ID = process.env.QS_SIGNER_DEVICE_ID || ''
const MAX_BODY = Number(process.env.QS_SIGNER_MAX_BODY) || 256 * 1024
const MODULE_PATH = path.resolve(process.env.QS_SIGNER_BDMS_MODULE || path.join(__dirname, 'vendor', 'bdms.node'))

if (!TOKEN && !ALLOW_ANONYMOUS) {
  console.error('[qs-signer] 拒绝启动：未设置 QS_SIGNER_TOKEN（本机调试可显式 QS_SIGNER_ALLOW_ANONYMOUS=1）')
  process.exit(1)
}

const maskDevice = (id) => {
  const value = String(id || '')
  return value.length <= 6 ? value : `${value.slice(0, 3)}***${value.slice(-3)}`
}

// —— 官方模块加载：一次 require，按设备 init（换设备要重新 init）——
let bdms = null
let loadError = ''
let initedDevice = ''
const loadBdms = () => {
  if (bdms) return bdms
  if (loadError) return null
  try {
    if (!fs.existsSync(MODULE_PATH)) throw new Error(`找不到 ${MODULE_PATH}`)
    const mod = require(MODULE_PATH)
    if (typeof mod.init !== 'function' || typeof mod.generateHttpSignatureHeaders !== 'function') {
      throw new Error('导出不符合预期（需要 init / generateHttpSignatureHeaders）')
    }
    bdms = mod
    console.log(`[qs-signer] bdms 模块已加载: ${MODULE_PATH}`)
    return bdms
  } catch (err) {
    loadError = String((err && err.message) || err)
    console.error(`[qs-signer] bdms 模块加载失败: ${loadError}（/sign 将返回 503，/healthz 仍可用）`)
    return null
  }
}

const deviceIdFromRequest = (url, headers, explicit) => {
  if (explicit) return String(explicit).trim()
  try {
    const parsed = new URL(String(url))
    for (const key of ['device_id', 'did', 'fp']) {
      const value = parsed.searchParams.get(key)
      if (value) return value.trim()
    }
  } catch {
    // URL 不合法就继续往下找
  }
  for (const name of ['x-device-id', 'device-id', 'device_id']) {
    if (headers && headers[name]) return String(headers[name]).trim()
  }
  return DEFAULT_DEVICE_ID
}

const ensureInit = (deviceId) => {
  const mod = loadBdms()
  if (!mod) throw new Error(loadError || 'bdms 模块不可用')
  const target = String(deviceId || DEFAULT_DEVICE_ID || '').trim()
  if (!target) throw new Error('缺少 device_id：请求里带 device_id（或 URL 查询参数 device_id/did/fp），或设置 QS_SIGNER_DEVICE_ID')
  if (initedDevice !== target) {
    mod.init({ deviceId: target })
    initedDevice = target
    console.log(`[qs-signer] 已绑定设备 ${maskDevice(target)}`)
  }
  return mod
}

const flattenHeaders = (headers) => {
  const lines = []
  for (const [name, value] of Object.entries(headers || {})) {
    if (!name || value === undefined || value === null) continue
    const items = Array.isArray(value) ? value : [value]
    for (const item of items) lines.push(`${name}\r\n${item}`)
  }
  return lines.join('\r\n')
}

const parseSignaturePairs = (raw) => {
  const fields = String(raw || '').split('\r\n').filter((t) => t.trim())
  const signed = {}
  for (let i = 0; i + 1 < fields.length; i += 2) signed[fields[i]] = fields[i + 1]
  return signed
}

/** 签名一次请求：返回需追加/覆盖的请求头（含服务端补的 x-ss-stub） */
const signRequest = ({ url, headers = {}, body, deviceId }) => {
  if (!url) throw new Error('url 不能为空')
  const target = ensureInit(deviceIdFromRequest(url, headers, deviceId))
  const outgoing = { ...headers }
  // 有 body 却没给 x-ss-stub 时补上（它是签名输入，也要随请求发出），大小写保持官方写法
  if (body && !Object.keys(outgoing).some((k) => k.toLowerCase() === 'x-ss-stub')) {
    outgoing['x-ss-stub'] = crypto.createHash('md5').update(String(body)).digest('hex').toUpperCase()
  }
  const signed = parseSignaturePairs(target.generateHttpSignatureHeaders(String(url), flattenHeaders(outgoing)))
  if (!signed['X-Helios'] && !signed['x-helios']) throw new Error('签名结果缺少 X-Helios')
  return { signed: { ...signed, ...(body ? { 'x-ss-stub': outgoing['x-ss-stub'] } : {}) }, deviceId: initedDevice }
}

const json = (res, status, payload) => {
  const text = JSON.stringify(payload)
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(text) })
  res.end(text)
}

const readBody = (req) => new Promise((resolve, reject) => {
  let size = 0
  const chunks = []
  req.on('data', (chunk) => {
    size += chunk.length
    if (size > MAX_BODY) {
      reject(Object.assign(new Error('请求体过大'), { status: 413 }))
      req.destroy()
      return
    }
    chunks.push(chunk)
  })
  req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
  req.on('error', reject)
})

const authorized = (req) => {
  if (!TOKEN) return true
  const header = String(req.headers.authorization || '')
  const bearer = header.toLowerCase().startsWith('bearer ') ? header.slice(7).trim() : ''
  const alt = String(req.headers['x-signer-token'] || '')
  return bearer === TOKEN || alt === TOKEN
}

const server = http.createServer(async (req, res) => {
  const started = Date.now()
  const url = String(req.url || '')
  const pathname = url.split('?')[0]

  const log = (status) => console.log(`[qs-signer] ${req.method} ${pathname} → ${status} (${Date.now() - started}ms)`)

  try {
    if (pathname === '/healthz') {
      log(200)
      return json(res, 200, {
        ok: true,
        service: SERVICE,
        version: VERSION,
        bdmsAvailable: Boolean(bdms) || (!loadError && fs.existsSync(MODULE_PATH)),
        deviceId: maskDevice(initedDevice || DEFAULT_DEVICE_ID),
        auth: Boolean(TOKEN),
        platform: `${process.platform} ${process.arch}`,
        node: process.version,
      })
    }

    if (!authorized(req)) {
      log(401)
      return json(res, 401, { ok: false, error: 'unauthorized', code: 'unauthorized' })
    }

    if (pathname === '/config') {
      log(200)
      return json(res, 200, {
        ok: true,
        service: SERVICE,
        version: VERSION,
        bdmsModule: MODULE_PATH,
        bdmsLoaded: Boolean(bdms),
        loadError,
        deviceId: maskDevice(initedDevice || DEFAULT_DEVICE_ID),
        identity: { device_id: initedDevice || DEFAULT_DEVICE_ID, source: initedDevice ? 'request' : (DEFAULT_DEVICE_ID ? 'env' : 'unset') },
      })
    }

    if (pathname === '/selftest') {
      try {
        const sampleUrl = 'https://api.qishui.com/luna/pc/track_v2?aid=386088&device_id=1&iid=2'
        const { signed } = signRequest({ url: sampleUrl, headers: { 'user-agent': 'LunaPC/selftest' }, deviceId: DEFAULT_DEVICE_ID || '1' })
        log(200)
        return json(res, 200, { ok: true, headers: Object.keys(signed), lengths: Object.fromEntries(Object.entries(signed).map(([k, v]) => [k, String(v).length])) })
      } catch (err) {
        log(503)
        return json(res, 503, { ok: false, error: String((err && err.message) || err), code: 'signer_error' })
      }
    }

    if (pathname === '/sign' && req.method === 'POST') {
      const raw = await readBody(req)
      let payload
      try {
        payload = JSON.parse(raw || '{}')
      } catch {
        log(400)
        return json(res, 400, { ok: false, error: 'invalid JSON', code: 'bad_request' })
      }
      const { url: target, headers = {}, body = '', device_id: deviceId } = payload
      try {
        const { signed } = signRequest({ url: target, headers, body, deviceId })
        log(200)
        // headers 嵌套给标准调用方；顶层扁平给 Meting 风格调用方
        return json(res, 200, { ok: true, headers: signed, ...signed, device_id: initedDevice, elapsed_ms: Date.now() - started })
      } catch (err) {
        log(503)
        return json(res, 503, { ok: false, error: String((err && err.message) || err), code: 'signer_error' })
      }
    }

    log(404)
    return json(res, 404, { ok: false, error: 'not found' })
  } catch (err) {
    const status = err && err.status ? err.status : 500
    log(status)
    return json(res, status, { ok: false, error: String((err && err.message) || err) })
  }
})

server.listen(PORT, BIND, () => {
  console.log(`[qs-signer] 监听 http://${BIND}:${PORT}（鉴权: ${TOKEN ? 'Bearer token' : '匿名（仅调试）'}）`)
  loadBdms()
})
