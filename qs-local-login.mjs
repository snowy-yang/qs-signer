#!/usr/bin/env node
// 汽水音乐「本机客户端登录」独立脚本 —— 不参与服务运行，需要时手动跑一次
//
// 做什么：官方 SodaMusic PC 客户端是 Chromium，登录态就存在本机
//   %APPDATA%\SodaMusic\Network\Cookies（SQLite）里，设备身份在 %APPDATA%\SodaMusic\DeviceV1
//   （gzip JSON，含 did/iid）。本脚本直接读出来写进 MusicServer 的 data/auth.json 的 qs 字段，
//   免去扫码登录。参考实现：YYF1337/PopDownloader（SaKongA/PopDownloader 的 fork）。
//
// 用法：
//   node qs-local-login.mjs                     # 读取 + 校验 + 写入 MusicServer 的 data/auth.json
//   node qs-local-login.mjs --print             # 只打印 sessionid，不落盘
//   node qs-local-login.mjs --no-verify         # 跳过 /luna/pc/me 校验
//   node qs-local-login.mjs --dir <目录>         # 指定客户端数据目录（默认 %APPDATA%\SodaMusic）
//   node qs-local-login.mjs --auth <文件>        # 指定 auth.json（默认同级 MusicServer/data/auth.json）
//
// 写入目标默认取同级 ../MusicServer（凭据归 MusicServer 管）；同级没有时须 --auth 显式指定。
// 校验需要官方签名模块（soda-mssdk/bdms.node 或 QS_MSSDK_DIR），没有就跳过校验只写入。
// 注意：MusicServer 在跑时 auth.json 已缓存，写完需重启服务才生效（脚本会提示）。
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { gunzipSync } from 'node:zlib'

const require = createRequire(import.meta.url)
const root = dirname(fileURLToPath(import.meta.url))
const musicServerDir = join(root, '..', 'MusicServer')

const argv = process.argv.slice(2)
const flag = (name) => argv.includes(name)
const value = (name) => {
  const i = argv.indexOf(name)
  return i >= 0 ? argv[i + 1] : ''
}

const dataDir = resolve(value('--dir') || process.env.QS_SODA_DATA_DIR || join(process.env.APPDATA || '', 'SodaMusic'))
const explicitAuth = value('--auth') || process.env.QS_AUTH_FILE || ''
const printOnly = flag('--print')
const skipVerify = flag('--no-verify')
const DEVICE_FILE = join(dataDir, 'DeviceV1')
const COOKIE_DB = join(dataDir, 'Network', 'Cookies')

const die = (msg) => {
  console.error(`✗ ${msg}`)
  process.exit(1)
}

// —— 1. 客户端设备身份（DeviceV1：gzip JSON 的 {did,iid}）——
const readDevice = () => {
  if (!existsSync(DEVICE_FILE)) return null
  const raw = readFileSync(DEVICE_FILE)
  let text
  try {
    text = gunzipSync(raw).toString('utf8')
  } catch {
    text = raw.toString('utf8')
  }
  const data = JSON.parse(text)
  return data?.did && data?.iid ? { did: String(data.did), iid: String(data.iid) } : null
}

// —— 2. 客户端登录态（Chromium cookie 库，复制副本后只读查询）——
const readSessionId = () => {
  if (!existsSync(COOKIE_DB)) die(`未找到客户端登录数据：${COOKIE_DB}\n  请先安装并登录官方汽水音乐 PC 客户端，或用 --dir 指定数据目录`)
  const tempDir = mkdtempSync(join(tmpdir(), 'qs-cookies-'))
  try {
    const copy = join(tempDir, 'Cookies')
    copyFileSync(COOKIE_DB, copy)
    for (const side of ['-wal', '-shm']) {
      if (existsSync(COOKIE_DB + side)) copyFileSync(COOKIE_DB + side, copy + side)
    }
    const { DatabaseSync } = require('node:sqlite')
    const db = new DatabaseSync(copy, { readOnly: true })
    try {
      const row = db.prepare(
        "SELECT value FROM cookies WHERE host_key IN ('.qishui.com', 'qishui.com') AND name = 'sessionid' LIMIT 1",
      ).get()
      return String(row?.value ?? '').trim()
    } finally {
      db.close()
    }
  } catch (err) {
    if (/EBUSY|locked|busy|unable to open/i.test(String(err?.message))) {
      die('客户端正在运行且 cookie 库被占用，请退出汽水音乐客户端后重试')
    }
    die(`读取 cookie 库失败: ${err?.message ?? err}`)
  } finally {
    rmSync(tempDir, { recursive: true, force: true })
  }
}

// —— 3. 可选：签名打 /luna/pc/me 校验（status_code === 0 视为有效）——
const findSigner = () => {
  const dirs = [process.env.QS_MSSDK_DIR, join(root, 'soda-mssdk')].filter(Boolean)
  for (const dir of dirs) {
    if (existsSync(join(dir, 'bdms.node'))) return join(dir, 'bdms.node')
  }
  return ''
}

const verify = async (sessionid, device) => {
  const modulePath = findSigner()
  if (!modulePath) return null
  try {
    const bdms = require(modulePath)
    bdms.init({ deviceId: device.did })
    const query = new URLSearchParams({
      aid: '386088', app_name: 'luna_pc', region: 'cn', geo_region: 'cn', os_region: 'cn', sim_region: '',
      device_id: device.did, cdid: '', iid: device.iid, version_name: '3.7.0', version_code: '30070000',
      channel: 'official', build_mode: 'master', network_carrier: '', ac: 'wifi', tz_name: 'Asia/Shanghai',
      resolution: '', device_platform: 'windows', device_type: 'Windows', os_version: 'Windows 11', fp: device.did,
    })
    const url = `https://api.qishui.com/luna/pc/me?${query}`
    const headers = { 'user-agent': 'LunaPC/3.7.0(452316191)', cookie: `sessionid=${sessionid}` }
    const lines = Object.entries(headers).map(([k, v]) => `${k}\r\n${v}`).join('\r\n')
    const parts = String(bdms.generateHttpSignatureHeaders(url, lines)).split('\r\n').filter(t => t.trim())
    for (let i = 0; i + 1 < parts.length; i += 2) headers[parts[i]] = parts[i + 1]
    const res = await fetch(url, { headers })
    if (res.status !== 200) return null
    const body = await res.json().catch(() => null)
    const code = body?.status_code
    if (code === 0) return true
    return code == null ? null : false
  } catch (err) {
    console.log(`! 校验失败（按未校验处理）: ${err?.message ?? err}`)
    return null
  }
}

const main = async () => {
  const device = readDevice()
  if (!device) console.log(`! 未读到客户端设备身份（${DEVICE_FILE}），校验时将跳过`)
  else console.log(`· 客户端设备: did=${device.did} iid=${device.iid}`)

  const sessionid = readSessionId()
  if (!sessionid) die('客户端未登录（cookie 库中没有 .qishui.com 的 sessionid），请先在客户端登录')

  let verified = null
  if (!skipVerify && device) {
    verified = await verify(sessionid, device)
    if (verified === false) die('客户端登录态已失效，请在汽水音乐客户端重新登录后再跑本脚本')
  }
  console.log(`· sessionid: ${sessionid.slice(0, 6)}…${sessionid.slice(-4)}（${sessionid.length} 字符）`)
  console.log(`· 校验: ${verified === true ? '有效' : verified === false ? '已失效' : skipVerify ? '已跳过（--no-verify）' : '无法判定（缺签名模块或网络异常）'}`)

  if (printOnly) {
    console.log(sessionid)
    return
  }

  const authPath = explicitAuth
    ? resolve(explicitAuth)
    : join(musicServerDir, 'data', 'auth.json')
  if (!explicitAuth && !existsSync(musicServerDir)) {
    die(`未找到同级 MusicServer 仓库（${musicServerDir}），请用 --auth <路径>/data/auth.json 指定写入目标`)
  }
  const auth = existsSync(authPath) ? JSON.parse(readFileSync(authPath, 'utf8')) : {}
  auth.qs = { ...(auth.qs || {}), sessionid, cookie: `sessionid=${sessionid}`, source: 'local-client', updatedAt: new Date().toISOString() }
  writeFileSync(authPath, `${JSON.stringify(auth, null, 2)}\n`)
  console.log(`✓ 已写入 ${authPath}（qs.sessionid）`)
  console.log('  MusicServer 在运行的话需要重启才生效（凭据已缓存）；之后 /login/status 的 qs.logged 应为 true')
}

main().catch(err => die(err?.message ?? String(err)))
