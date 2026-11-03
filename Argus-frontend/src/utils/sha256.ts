/**
 * SHA-256 工具集
 *
 * 提供三种能力：
 * 1. createSha256()    —— 增量摘要，支持流式喂数据
 * 2. sha256Hex(buffer) —— 单块计算，走浏览器原生 Web Crypto（更快）
 * 3. hashFileStream()  —— 按块读取 File 计算整体指纹，带进度回调
 *
 * 为什么要自己实现增量版本：Web Crypto 的 subtle.digest 只能一次性对完整
 * ArrayBuffer 求摘要，而分片上传支持最大 256MB 文件，全量读入内存不可接受。
 *
 * 注：项目 tsconfig 开启了 noUncheckedIndexedAccess，TypedArray 的索引读取
 * 会被推断为 number | undefined，故数值访问统一加非空断言（下标恒在范围内）。
 */

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
])

function rotr(x: number, n: number): number {
  return ((x >>> n) | (x << (32 - n))) >>> 0
}

export interface Sha256Digest {
  /** 追加一段字节数据 */
  update(data: Uint8Array): void
  /** 结束填充并返回十六进制摘要（调用后实例不可复用） */
  hex(): string
}

export function createSha256(): Sha256Digest {
  const h = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ])
  const buf = new Uint8Array(64)
  let bufLen = 0
  let byteLength = 0

  function processBlock(block: Uint8Array, offset: number): void {
    const w = new Uint32Array(64)

    // 消息扩展：前 16 个 32 位字直接来自数据块
    for (let i = 0; i < 16; i++) {
      const j = offset + i * 4
      w[i] =
        (((block[j]! << 24) |
          (block[j + 1]! << 16) |
          (block[j + 2]! << 8) |
          block[j + 3]!) >>>
          0)
    }
    for (let i = 16; i < 64; i++) {
      const x = w[i - 15]!
      const y = w[i - 2]!
      const s0 = rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3)
      const s1 = rotr(y, 17) ^ rotr(y, 19) ^ (y >>> 10)
      w[i] = (w[i - 16]! + s0 + w[i - 7]! + s1) >>> 0
    }

    // 64 轮压缩
    let a = h[0]!
    let b = h[1]!
    let c = h[2]!
    let d = h[3]!
    let e = h[4]!
    let f = h[5]!
    let g = h[6]!
    let hh = h[7]!

    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
      const ch = ((e & f) ^ (~e & g)) >>> 0
      const t1 = (hh + S1 + ch + SHA256_K[i]! + w[i]!) >>> 0
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0
      const t2 = (S0 + maj) >>> 0
      hh = g
      g = f
      f = e
      e = (d + t1) >>> 0
      d = c
      c = b
      b = a
      a = (t1 + t2) >>> 0
    }

    h[0] = (h[0]! + a) >>> 0
    h[1] = (h[1]! + b) >>> 0
    h[2] = (h[2]! + c) >>> 0
    h[3] = (h[3]! + d) >>> 0
    h[4] = (h[4]! + e) >>> 0
    h[5] = (h[5]! + f) >>> 0
    h[6] = (h[6]! + g) >>> 0
    h[7] = (h[7]! + hh) >>> 0
  }

  return {
    update(data: Uint8Array): void {
      byteLength += data.length
      let offset = 0

      // 先填满上次残留的缓冲区
      if (bufLen > 0) {
        const take = Math.min(64 - bufLen, data.length)
        buf.set(data.subarray(0, take), bufLen)
        bufLen += take
        offset = take
        if (bufLen === 64) {
          processBlock(buf, 0)
          bufLen = 0
        }
      }
      // 整块直接压缩
      while (offset + 64 <= data.length) {
        processBlock(data, offset)
        offset += 64
      }
      // 剩余不足一块留待下次
      if (offset < data.length) {
        buf.set(data.subarray(offset))
        bufLen = data.length - offset
      }
    },

    hex(): string {
      const bitLength = byteLength * 8
      const padLen = bufLen < 56 ? 56 - bufLen : 120 - bufLen
      const tail = new Uint8Array(padLen + 8)
      tail[0] = 0x80
      const hi = Math.floor(bitLength / 0x100000000)
      const lo = bitLength >>> 0
      tail[padLen] = (hi >>> 24) & 0xff
      tail[padLen + 1] = (hi >>> 16) & 0xff
      tail[padLen + 2] = (hi >>> 8) & 0xff
      tail[padLen + 3] = hi & 0xff
      tail[padLen + 4] = (lo >>> 24) & 0xff
      tail[padLen + 5] = (lo >>> 16) & 0xff
      tail[padLen + 6] = (lo >>> 8) & 0xff
      tail[padLen + 7] = lo & 0xff

      // 把残留数据与填充拼接后按 64 字节块压缩（不复用 update，避免长度被二次累加）
      let offset = 0
      if (bufLen > 0) {
        const take = Math.min(64 - bufLen, tail.length)
        buf.set(tail.subarray(0, take), bufLen)
        if (bufLen + take === 64) {
          processBlock(buf, 0)
          offset = take
        } else {
          // padLen 设计保证不会走到这里，保险起见按未满块处理
          offset = take
        }
        bufLen = 0
      }
      while (offset < tail.length) {
        const next = Math.min(offset + 64, tail.length)
        const block = new Uint8Array(64)
        block.set(tail.subarray(offset, next))
        processBlock(block, 0)
        offset = next
      }

      let out = ''
      for (let i = 0; i < 8; i++) {
        out += h[i]!.toString(16).padStart(8, '0')
      }
      return out
    },
  }
}

/** 单块数据的 SHA-256（十六进制），走 Web Crypto */
export async function sha256Hex(buffer: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', buffer)
  const view = new Uint8Array(digest)
  let out = ''
  for (let i = 0; i < view.length; i++) {
    out += view[i]!.toString(16).padStart(2, '0')
  }
  return out
}

/**
 * 流式计算文件指纹：按 readSize 分块读取，onProgress 收到 0~100 的整数百分比。
 * 内存占用恒定为 readSize（默认 4MB），不受文件大小影响。
 */
export async function hashFileStream(
  file: File,
  readSize: number,
  onProgress: (percent: number) => void,
): Promise<string> {
  const hasher = createSha256()
  const total = file.size || 1
  for (let offset = 0; offset < file.size; offset += readSize) {
    const slice = file.slice(offset, Math.min(offset + readSize, file.size))
    hasher.update(new Uint8Array(await slice.arrayBuffer()))
    onProgress(Math.min(99, Math.round(((offset + readSize) / total) * 100)))
  }
  onProgress(100)
  return hasher.hex()
}
