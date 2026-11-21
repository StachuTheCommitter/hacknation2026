// Klient API: cookie sesji + nagłówek CSRF, mały cache dla useApi, strumień zdarzeń SSE.
import { useCallback, useEffect, useRef, useState } from 'react'

export class ApiError extends Error {
  status: number
  details: unknown
  constructor(status: number, message: string, details?: unknown) {
    super(message)
    this.status = status
    this.details = details
  }
}

function csrf(): string {
  const m = document.cookie.match(/(?:^|; )asi_csrf=([^;]+)/)
  return m ? decodeURIComponent(m[1]) : ''
}

let onUnauthorized: () => void = () => {}
export function setUnauthorizedHandler(fn: () => void) { onUnauthorized = fn }

export async function api<T = any>(path: string, opts: { method?: string; body?: unknown; form?: FormData; raw?: boolean } = {}): Promise<T> {
  const method = opts.method || (opts.body !== undefined || opts.form ? 'POST' : 'GET')
  const headers: Record<string, string> = {}
  if (method !== 'GET') headers['X-CSRF-Token'] = csrf()
  let body: BodyInit | undefined
  if (opts.form) body = opts.form
  else if (opts.body !== undefined) { headers['Content-Type'] = 'application/json'; body = JSON.stringify(opts.body) }
  const res = await fetch('/api/v1' + path, { method, headers, body, credentials: 'same-origin' })
  if (res.status === 401 && !path.startsWith('/auth/login')) onUnauthorized()
  if (!res.ok) {
    let msg = res.statusText, details: unknown
    try { const j = await res.json(); msg = j.error?.message || msg; details = j.error?.details } catch { /* brak treści */ }
    throw new ApiError(res.status, msg, details)
  }
  if (opts.raw) return res as unknown as T
  if (res.status === 204) return undefined as T
  return res.json()
}

const cache = new Map<string, unknown>()

// useApi – pobiera dane, pokazuje ostatni wynik z cache od razu (szybkie przełączanie widoków).
export function useApi<T = any>(path: string | null, deps: unknown[] = []) {
  const [data, setData] = useState<T | undefined>(path ? (cache.get(path) as T | undefined) : undefined)
  const [error, setError] = useState<ApiError | null>(null)
  const [loading, setLoading] = useState(false)
  const seq = useRef(0)
  const load = useCallback(async () => {
    if (!path) return
    const n = ++seq.current
    setLoading(true)
    try {
      const d = await api<T>(path)
      if (n === seq.current) { cache.set(path, d); setData(d); setError(null) }
    } catch (e) {
      if (n === seq.current) setError(e as ApiError)
    } finally {
      if (n === seq.current) setLoading(false)
    }
  }, [path])
  useEffect(() => {
    if (path && cache.has(path)) setData(cache.get(path) as T)
    load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, ...deps])
  return { data, error, loading, reload: load, setData }
}

// useEvents – nasłuch zdarzeń serwera (SSE) z odświeżaniem z opóźnieniem.
export function useEvents(types: string[], fn: () => void, delay = 800) {
  const fnRef = useRef(fn)
  fnRef.current = fn
  useEffect(() => {
    const es = new EventSource('/api/v1/events')
    let t: number | undefined
    const h = () => { window.clearTimeout(t); t = window.setTimeout(() => fnRef.current(), delay) }
    types.forEach(ty => es.addEventListener(ty, h))
    return () => { window.clearTimeout(t); es.close() }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [types.join(',')])
}

export function qs(params: Record<string, string | number | boolean | undefined | null>) {
  const u = new URLSearchParams()
  Object.entries(params).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== '') u.set(k, String(v)) })
  const s = u.toString()
  return s ? '?' + s : ''
}

export function download(path: string) {
  const a = document.createElement('a')
  a.href = '/api/v1' + path
  a.rel = 'noopener'
  document.body.appendChild(a)
  a.click()
  a.remove()
}
