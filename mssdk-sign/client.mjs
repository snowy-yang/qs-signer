// mssdk-sign 的 Node 客户端示例(免依赖,Node 18+)
//
// 用法:
//   node client.mjs                      # 自检:打 /healthz + 签一次 track_v2(不发真实请求)
//   node client.mjs --send               # 顺带把签名后的请求发给 api.qishui.com 验证
//
// 集成到 MusicServer 时,把 signQishuiRequest() 换成这个 HTTP 调用即可
// (签名输入必须与真实发出的头完全一致,含 x-ss-stub)。

const BASE = process.env.MSSDK_SIGN_URL ?? 'http://127.0.0.1:16889'
const TOKEN = process.env.MSSDK_SIGN_TOKEN ?? ''

const headers0 = (extra = {}) => (TOKEN ? { authorization: `Bearer ${TOKEN}`, ...extra } : extra)

/** 调本地签名服务;返回需要追加到请求上的头 */
export async function signRequest(url, headers, body) {
  const res = await fetch(`${BASE}/sign`, {
    method: 'POST',
    headers: headers0({ 'content-type': 'application/json' }),
    body: JSON.stringify({ url, headers, body }),
  })
  const json = await res.json().catch(() => ({ ok: false, error: `HTTP ${res.status}` }))
  if (!json.ok) throw new Error(json.error ?? `签名失败 HTTP ${res.status}`)
  return { headers: json.headers, added: json.added ?? {}, elapsed_ms: json.elapsed_ms }
}

export async function healthz() {
  const res = await fetch(`${BASE}/healthz`)
  return res.json()
}

import { pathToFileURL } from 'node:url'

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const health = await healthz()
  console.log('healthz:', health)

  // 与 sdk/qs/mssdk.ts 的 PC 通道同构:URL 带 device_id,headers 是真实要发出的那份
  const deviceId = process.env.QS_DEVICE_ID ?? '1219822735468811019'
  const iid = process.env.QS_IID ?? '1219822735468829019'
  const body = JSON.stringify({ track_id: '7501674235158431760', media_type: 'track', queue_type: 'search_one_track', scene_name: 'search' })
  const q = new URLSearchParams({
    aid: '386088', app_name: 'luna_pc', region: 'cn', geo_region: 'cn', os_region: 'cn', sim_region: '',
    device_id: deviceId, cdid: '', iid, version_name: '3.7.0', version_code: '30070000',
    channel: 'official', build_mode: 'master', network_carrier: '', ac: 'wifi', tz_name: 'Asia/Shanghai',
    resolution: '', device_platform: 'windows', device_type: 'Windows', os_version: 'Windows 11', fp: deviceId,
  })
  const url = `https://api.qishui.com/luna/pc/track_v2?${q}`
  const headers = {
    'content-type': 'application/json; charset=utf-8',
    'user-agent': 'LunaPC/3.7.0(452316191)',
    'x-luna-background-type': 'foreground',
    'x-luna-is-background-req': '0',
    'x-luna-is-local-user': '0',
    'x-tt-trace-id': `00-${'0'.repeat(16)}-${'0'.repeat(16)}-01`,
  }

  const signed = await signRequest(url, headers, body)
  console.log('签名头:', Object.keys(signed.headers), `(${signed.elapsed_ms}ms)`, signed.added)

  if (process.argv.includes('--send')) {
    const r = await fetch(url, { method: 'POST', headers: { ...headers, ...signed.headers, ...signed.added }, body })
    const t = await r.text()
    console.log(`真实请求: HTTP ${r.status} ${t.length} 字节`)
    if (t) {
      const j = JSON.parse(t)
      const vm = typeof j?.track_player?.video_model === 'string' ? JSON.parse(j.track_player.video_model) : j?.track_player?.video_model
      console.log(`  曲目: ${j?.track?.name} 曲长 ${j?.track?.duration}ms 试听 ${vm?.video_duration}s`)
    } else {
      console.log('  空 body = 签名没被接受')
    }
  }
}
