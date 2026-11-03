import { reactive } from 'vue'
import {
  initDocumentUpload,
  uploadDocumentChunk,
  completeDocumentUpload,
} from '@/api/document'
import { hashFileStream, sha256Hex } from '@/utils/sha256'

/**
 * 分片上传编排 composable
 *
 * 供 UploadDialog.vue 使用，职责：
 * 1. 计算整文件 SHA-256 指纹（流式计算，内存占用恒定，不随文件大小增长）
 * 2. 初始化上传会话（指纹命中已有文件时后端直接秒传）
 * 3. 逐分片上传（跳过断点续传中已上传的分片，单分片失败自动重试）
 * 4. 通知后端合并分片，完成上传
 *
 * 分片大小固定 8MB —— 必须小于后端 MAX_CHUNK_SIZE(10MB) 限制。
 */

type UploadStage = '' | 'hashing' | 'init' | 'uploading' | 'completing'

/** 分片大小，需小于后端 MAX_CHUNK_SIZE（10MB） */
const CHUNK_SIZE = 8 * 1024 * 1024
/** 计算整文件指纹时的分块读取大小 */
const HASH_READ_SIZE = 4 * 1024 * 1024
/** 单个分片失败后的最大自动重试次数（不含首次） */
const MAX_CHUNK_RETRY = 2

export function useChunkedUpload() {
  const state = reactive({
    /** 是否有分片上传任务在进行（含指纹计算阶段） */
    isUploading: false,
    /** 总进度 0~100 */
    progress: 0,
    /** 最近一次失败的错误信息，空字符串表示无错误 */
    error: '',
    /** 当前阶段，用于对话框展示分阶段文案 */
    stage: '' as UploadStage,
    /** 指纹计算阶段的进度文案 */
    hashingProgress: '',
    /** 分片进度（uploading 阶段） */
    chunkProgress: { uploaded: 0, total: 0 },
  })

  let controller: AbortController | null = null

  function sleep(ms: number, signal?: AbortSignal): Promise<void> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(resolve, ms)
      signal?.addEventListener(
        'abort',
        () => {
          clearTimeout(timer)
          reject(new DOMException('Aborted', 'AbortError'))
        },
        { once: true },
      )
    })
  }

  /** 上传单个分片，失败自动重试 MAX_CHUNK_RETRY 次 */
  async function uploadChunkWithRetry(
    file: File,
    index: number,
    uploadId: string,
    signal: AbortSignal,
  ): Promise<void> {
    const start = index * CHUNK_SIZE
    const end = Math.min(start + CHUNK_SIZE, file.size)
    const blob = file.slice(start, end)
    // 分片哈希对原始字节计算（单分片 8MB，走 Web Crypto 即可）
    const chunkHash = await sha256Hex(await blob.arrayBuffer())

    let attempt = 0
    for (;;) {
      try {
        await uploadDocumentChunk(
          { uploadId, chunkIndex: index, chunkHash, chunk: blob },
          undefined,
          signal,
        )
        return
      } catch (err) {
        if (signal.aborted) throw err
        attempt += 1
        if (attempt > MAX_CHUNK_RETRY) throw err
        await sleep(500 * attempt, signal)
      }
    }
  }

  /**
   * 执行完整的分片上传流程。
   * 失败时抛出异常并写入 state.error（调用方无需重复提示）。
   */
  async function uploadFile(file: File, groupId: number): Promise<void> {
    if (state.isUploading) {
      throw new Error('已有上传任务进行中，请等待完成或取消')
    }
    controller = new AbortController()
    const signal = controller.signal
    state.isUploading = true
    state.error = ''
    state.progress = 0
    state.stage = 'hashing'
    state.hashingProgress = ''
    state.chunkProgress = { uploaded: 0, total: 0 }

    try {
      // 1. 整文件指纹（进度占 0~5%）
      const fileHash = await hashFileStream(file, HASH_READ_SIZE, (percent) => {
        state.hashingProgress = `正在计算文件指纹 ${percent}%`
        state.progress = Math.round(percent * 0.05)
      })
      if (signal.aborted) throw new DOMException('Aborted', 'AbortError')

      // 2. 初始化会话 / 秒传判断（进度 6%）
      state.stage = 'init'
      state.progress = 6
      const init = await initDocumentUpload(
        {
          groupId,
          fileName: file.name,
          fileSize: file.size,
          contentType: file.type || 'application/octet-stream',
          fileHash,
          chunkSize: CHUNK_SIZE,
          chunkCount: Math.max(1, Math.ceil(file.size / CHUNK_SIZE)),
        },
        signal,
      )

      if (init.instantUpload) {
        // 秒传命中：后端直接复用已有文件，无需任何分片操作
        state.progress = 100
        return
      }
      if (!init.uploadId) {
        throw new Error('初始化上传失败：未获得上传会话')
      }

      // 3. 逐分片上传（进度 6~95%），跳过断点续传已上传的分片
      const total = init.chunkCount ?? Math.max(1, Math.ceil(file.size / CHUNK_SIZE))
      state.stage = 'uploading'
      state.chunkProgress.total = total
      const uploadedSet = new Set(init.uploadedChunks ?? [])
      state.chunkProgress.uploaded = uploadedSet.size

      for (let index = 0; index < total; index++) {
        if (signal.aborted) throw new DOMException('Aborted', 'AbortError')
        if (uploadedSet.has(index)) continue
        await uploadChunkWithRetry(file, index, init.uploadId, signal)
        uploadedSet.add(index)
        state.chunkProgress.uploaded = uploadedSet.size
        state.progress = 6 + Math.round((uploadedSet.size / total) * 89)
      }

      // 4. 合并分片（进度 96~100%）
      state.stage = 'completing'
      state.progress = 96
      await completeDocumentUpload(init.uploadId, signal)
      state.progress = 100
    } catch (err) {
      state.error = signal.aborted
        ? '上传已取消'
        : err instanceof Error && err.message
          ? err.message
          : '上传失败，请重试'
      throw err
    } finally {
      state.isUploading = false
      state.stage = ''
      controller = null
    }
  }

  /** 取消当前上传（若有） */
  function cancel(): void {
    controller?.abort()
  }

  /** 重置全部状态（打开对话框时调用） */
  function reset(): void {
    controller?.abort()
    controller = null
    state.isUploading = false
    state.progress = 0
    state.error = ''
    state.stage = ''
    state.hashingProgress = ''
    state.chunkProgress = { uploaded: 0, total: 0 }
  }

  // 通过 getter/setter 暴露状态：调用方用 reactive() 包装本对象时，
  // Vue 的 reactive 代理会透传 getter/setter，读写均落到内部 state。
  return {
    uploadFile,
    cancel,
    reset,
    get isUploading() {
      return state.isUploading
    },
    set isUploading(v: boolean) {
      state.isUploading = v
    },
    get progress() {
      return state.progress
    },
    set progress(v: number) {
      state.progress = v
    },
    get error() {
      return state.error
    },
    set error(v: string) {
      state.error = v
    },
    get stage() {
      return state.stage
    },
    set stage(v: UploadStage) {
      state.stage = v
    },
    get hashingProgress() {
      return state.hashingProgress
    },
    set hashingProgress(v: string) {
      state.hashingProgress = v
    },
    get chunkProgress() {
      return state.chunkProgress
    },
    set chunkProgress(v: { uploaded: number; total: number }) {
      state.chunkProgress = v
    },
  }
}
