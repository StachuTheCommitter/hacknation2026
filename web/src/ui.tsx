// Małe, wielokrotnie używane elementy interfejsu.
import { createContext, ReactNode, useCallback, useContext, useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'

// ---------- kontekst użytkownika ----------
export type Me = { id: string; email: string; display_name: string; role: string; role_description: string; permissions: string[] }
export const AuthCtx = createContext<{ me: Me | null; can: (p: string) => boolean; refresh: () => void; meta: any }>({ me: null, can: () => false, refresh: () => {}, meta: {} })
export const useAuth = () => useContext(AuthCtx)

// ---------- powiadomienia ----------
type Toast = { id: number; text: string; err?: boolean }
const ToastCtx = createContext<(text: string, err?: boolean) => void>(() => {})
export const useToast = () => useContext(ToastCtx)
export function ToastProvider({ children }: { children: ReactNode }) {
  const [list, setList] = useState<Toast[]>([])
  const push = useCallback((text: string, err?: boolean) => {
    const id = Date.now() + Math.random()
    setList(l => [...l, { id, text, err }])
    setTimeout(() => setList(l => l.filter(t => t.id !== id)), err ? 7000 : 3500)
  }, [])
  return <ToastCtx.Provider value={push}>{children}<div className="toast-wrap">{list.map(t => <div key={t.id} className={'toast' + (t.err ? ' err' : '')}>{t.text}</div>)}</div></ToastCtx.Provider>
}

// ---------- formatowanie ----------
const rtf = new Intl.RelativeTimeFormat('pl', { numeric: 'auto' })
export function ago(iso?: string | null): string {
  if (!iso) return '—'
  const d = (new Date(iso).getTime() - Date.now()) / 1000
  const a = Math.abs(d)
  if (a < 45) return 'przed chwilą'
  if (a < 3600) return rtf.format(Math.round(d / 60), 'minute')
  if (a < 86400) return rtf.format(Math.round(d / 3600), 'hour')
  if (a < 86400 * 30) return rtf.format(Math.round(d / 86400), 'day')
  return new Date(iso).toLocaleDateString('pl-PL')
}
export function dt(iso?: string | null): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('pl-PL', { dateStyle: 'short', timeStyle: 'short' })
}
export function dur(sec?: number | null): string {
  if (sec === undefined || sec === null || sec < 0) return '—'
  if (sec < 60) return `${Math.round(sec)} s`
  if (sec < 3600) return `${Math.round(sec / 60)} min`
  const h = Math.floor(sec / 3600), m = Math.round((sec % 3600) / 60)
  return m ? `${h} h ${m} min` : `${h} h`
}
export const num = (n?: number) => (n ?? 0).toLocaleString('pl-PL')
export const pct = (n?: number) => `${Math.round((n ?? 0) * 100)}%`

// ---------- znaczniki ----------
export function Score({ v, title }: { v?: number; title?: string }) {
  const s = v ?? 0
  return <span className={'score' + (s >= 60 ? ' s3' : s >= 30 ? ' s2' : '')} title={title}>{s}</span>
}

const stateMap: Record<string, [string, string]> = {
  ACTIVE: ['green', 'aktywny'], SUSPECT: ['amber', 'podejrzany'], INACTIVE: ['', 'nieaktywny'],
  RUNNING: ['blue', 'w toku'], COMPLETED: ['green', 'zakończony'], PAUSED_WINDOW: ['amber', 'poza oknem'], PAUSED_MANUAL: ['amber', 'wstrzymany'],
  PENDING: ['', 'w kolejce'], CANCELLED: ['', 'anulowany'], SUPERSEDED: ['', 'zastąpiony'], FAILED: ['red', 'błąd'],
}
export function State({ s }: { s: string }) {
  const [c, l] = stateMap[s] || ['', s.toLowerCase()]
  return <span className="nowrap"><span className={'dot ' + c} />{l}</span>
}

export const catLabel: Record<string, string> = {
  admin_panel: 'panel admina', debug_exposure: 'ekspozycja debug', cleartext_login: 'logowanie po HTTP', staging: 'staging / test',
  eol_software: 'bez wsparcia (EOL)', iot: 'IoT', default_page: 'strona domyślna', tls_issue: 'problem TLS', exposed_service: 'usługa wystawiona',
  weak_config: 'słaba konfiguracja', info_disclosure: 'ujawnienie wersji', cms: 'CMS', framework: 'framework', app_server: 'serwer aplikacyjny',
  web_server: 'serwer WWW', technology: 'technologia', manual: 'ręcznie',
}
const catColor: Record<string, string> = {
  admin_panel: 'red', debug_exposure: 'red', cleartext_login: 'amber', staging: 'amber', eol_software: 'amber', iot: 'violet', tls_issue: 'amber',
  exposed_service: 'amber', cms: 'blue', framework: 'blue', app_server: 'blue', default_page: '',
}
export function Cat({ c, conf }: { c: string; conf?: number }) {
  return <span className={'badge ' + (catColor[c] || '')} title={conf !== undefined ? `pewność ${pct(conf)}` : undefined}>{catLabel[c] || c}</span>
}

export function Labels({ l }: { l?: string[] }) {
  if (!l || !l.length) return null
  return <>{l.map(x => <span key={x} className={'badge ' + (x.startsWith('PERIODIC') ? 'violet' : x === 'FLAPPING' ? 'amber' : '')} title={labelHelp(x)}>{labelText(x)}</span>)}</>
}
function labelText(x: string) {
  if (x === 'FLAPPING') return 'niestabilny'
  if (x.startsWith('PERIODIC')) return 'okresowy: ' + x.slice(9, -1).toLowerCase()
  return x.toLowerCase()
}
function labelHelp(x: string) {
  if (x === 'FLAPPING') return 'Częste zmiany dostępności w ostatnich przebiegach (flap rate ≥ 0,4)'
  if (x.startsWith('PERIODIC')) return 'Dostępność zależy od pory dnia – braki poza tymi porami nie oznaczają awarii'
  return x
}

export const changeText: Record<string, string> = {
  HOST_NEW: 'nowy host', HOST_GONE: 'host zniknął', HOST_RETURNED: 'host wrócił', SERVICE_NEW: 'nowa usługa', SERVICE_GONE: 'usługa zniknęła',
  SERVICE_RETURNED: 'usługa wróciła', SERVICE_CHANGED: 'zmiana usługi', HTTP_CHANGED: 'zmiana WWW', TLS_CHANGED: 'zmiana certyfikatu',
  IDENTITY_CHANGED: 'inne urządzenie', SIGNATURE_MATCH_NEW: 'nowa sygnatura', SIGNATURE_MATCH_GONE: 'sygnatura znikła', STATE_FLAPPING: 'niestabilność',
  STATE_PERIODIC: 'okresowość', DOMAIN_OUT_OF_SCOPE: 'domena poza scope',
}
const changeColor: Record<string, string> = {
  HOST_NEW: 'blue', SERVICE_NEW: 'blue', HOST_GONE: '', SERVICE_GONE: '', HOST_RETURNED: 'green', SERVICE_RETURNED: 'green',
  SERVICE_CHANGED: 'amber', HTTP_CHANGED: 'amber', TLS_CHANGED: 'amber', IDENTITY_CHANGED: 'red', SIGNATURE_MATCH_NEW: 'red', STATE_FLAPPING: 'amber', STATE_PERIODIC: 'violet',
}
export function ChangeType({ t }: { t: string }) {
  return <span className={'badge ' + (changeColor[t] || '')}>{changeText[t] || t}</span>
}

export function Sev({ s }: { s: string }) {
  const c = s === 'High' ? 'red' : s === 'Medium' ? 'amber' : s === 'Low' ? 'amber' : ''
  return <span className={'badge ' + c}>{s}</span>
}

const statusPL: Record<string, string> = { open: 'otwarte', false_positive: 'false positive', risk_accepted: 'ryzyko zaakceptowane', mitigated: 'naprawione', out_of_scope: 'poza zakresem' }
export function FStatus({ s }: { s: string }) {
  const c = s === 'open' ? 'blue' : s === 'false_positive' ? '' : s === 'mitigated' ? 'green' : 'violet'
  return <span className={'badge ' + c}>{statusPL[s] || s}</span>
}

export function Conf({ v }: { v?: number }) {
  const x = v ?? 0
  const t = x >= 0.8 ? 'pewne' : x >= 0.5 ? 'prawdopodobne' : 'przypuszczenie'
  return <span className={x >= 0.8 ? '' : x >= 0.5 ? 'muted' : 'faint'} title={`pewność ${pct(x)} (${t})`}>{pct(x)}</span>
}

export function Breakdown({ items }: { items?: { label: string; points: number }[] }) {
  if (!items || !items.length) return <span className="faint">brak czynników</span>
  return <span className="why">{items.filter(i => i.points !== 0).map(i => `${i.points > 0 ? '+' : ''}${i.points} ${i.label}`).join(' · ')}</span>
}

// ---------- układ ----------
export function Top({ title, crumbs, children }: { title: ReactNode; crumbs?: ReactNode; children?: ReactNode }) {
  return <div className="top"><div className="grow">{crumbs && <div className="crumbs">{crumbs}</div>}<h1>{title}</h1></div>{children}</div>
}

export function Panel({ title, actions, children, pad = true }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; pad?: boolean }) {
  return <section className="panel">{title !== undefined && <div className="ph"><h2>{title}</h2><div className="spacer" />{actions}</div>}{pad ? <div className="pb">{children}</div> : children}</section>
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return <div className="empty"><b>{title}</b>{children}</div>
}

export function Tabs({ items, value, onChange }: { items: [string, string][]; value: string; onChange: (v: string) => void }) {
  return <div className="tabs">{items.map(([k, l]) => <button key={k} className={value === k ? 'active' : ''} onClick={() => onChange(k)}>{l}</button>)}</div>
}

export function Modal({ title, onClose, children, footer, wide }: { title: ReactNode; onClose: () => void; children: ReactNode; footer?: ReactNode; wide?: boolean }) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [onClose])
  return <div className="overlay" onMouseDown={e => { if (e.target === e.currentTarget) onClose() }}>
    <div className={'modal' + (wide ? ' wide' : '')} role="dialog"><div className="mh"><h2 style={{ margin: 0 }}>{title}</h2><div className="spacer" /><button className="ghost sm" onClick={onClose}>Zamknij</button></div>
      <div className="mb">{children}</div>{footer && <div className="mf">{footer}</div>}</div>
  </div>
}

export function ErrorNote({ e }: { e: any }) {
  if (!e) return null
  const det = e.details
  return <div className="notice err">{e.message}{Array.isArray(det) && det.length > 0 && <ul style={{ margin: '6px 0 0', paddingLeft: 18 }}>{det.slice(0, 12).map((d: any, i: number) => <li key={i}>{typeof d === 'string' ? d : d.path ? `${d.path}: ${d.message}` : JSON.stringify(d)}</li>)}</ul>}</div>
}

export function Pager({ total, limit, offset, onPage }: { total: number; limit: number; offset: number; onPage: (o: number) => void }) {
  if (total <= limit) return <div className="hint" style={{ padding: '8px 10px' }}>{num(total)} pozycji</div>
  return <div className="row" style={{ padding: '8px 10px' }}>
    <span className="hint">{num(offset + 1)}–{num(Math.min(offset + limit, total))} z {num(total)}</span><div className="spacer" />
    <button className="sm" disabled={offset === 0} onClick={() => onPage(Math.max(0, offset - limit))}>Poprzednie</button>
    <button className="sm" disabled={offset + limit >= total} onClick={() => onPage(offset + limit)}>Następne</button>
  </div>
}

// Pole wyszukiwania – skrót „/”.
export function SearchBox({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder?: string }) {
  const ref = useRef<HTMLInputElement>(null)
  const [v, setV] = useState(value)
  useEffect(() => setV(value), [value])
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement
      if (e.key === '/' && !['INPUT', 'TEXTAREA', 'SELECT'].includes(t.tagName)) { e.preventDefault(); ref.current?.focus() }
    }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [])
  useEffect(() => { const t = setTimeout(() => { if (v !== value) onChange(v) }, 350); return () => clearTimeout(t) }, [v])
  return <div className="search"><input ref={ref} value={v} onChange={e => setV(e.target.value)} placeholder={placeholder} onKeyDown={e => { if (e.key === 'Enter') onChange(v); if (e.key === 'Escape') { setV(''); onChange('') } }} /></div>
}

export function HostLink({ ip, children }: { ip: string; children?: ReactNode }) {
  return <Link className="mono" to={`/hosts/${ip}`}>{children ?? ip}</Link>
}

// klucz encji → czytelny opis
export function keyLabel(key: string) {
  const p = key.split('/')
  if (p.length >= 5) return `${p[3]}://${p[4] !== '-' ? p[4] : p[0]}:${p[2]}`
  if (p.length === 3) return `${p[0]} ${p[2]}/${p[1]}`
  return key
}

// ---------- wykresy (SVG) ----------
export function Bars({ series, height = 120 }: { series: { label: string; values: { v: number; color: string; name: string }[] }[]; height?: number }) {
  if (!series.length) return <Empty title="Brak zakończonych przebiegów" />
  const max = Math.max(1, ...series.map(s => s.values.reduce((a, b) => a + b.v, 0)))
  const w = 28, gap = 10
  const W = series.length * (w + gap)
  return <svg className="chart" width="100%" viewBox={`0 0 ${Math.max(W, 200)} ${height + 18}`} preserveAspectRatio="xMinYMax meet" role="img">
    {series.map((s, i) => {
      let y = height
      return <g key={i} transform={`translate(${i * (w + gap)},0)`}>
        {s.values.map((v, j) => { const h = (v.v / max) * (height - 4); y -= h; return <rect key={j} x={0} y={y} width={w} height={Math.max(h, v.v ? 1 : 0)} fill={v.color} rx={1}><title>{`${s.label}: ${v.name} ${v.v}`}</title></rect> })}
        <text x={w / 2} y={height + 13} textAnchor="middle">{s.label}</text>
      </g>
    })}
  </svg>
}

export function Heatmap({ data }: { data: (number | null)[][] }) {
  const days = ['pn', 'wt', 'śr', 'cz', 'pt', 'sb', 'nd']
  return <div className="heat">
    <span />{Array.from({ length: 24 }, (_, h) => <span key={h} style={{ textAlign: 'center' }}>{h % 6 === 0 ? h : ''}</span>)}
    {data.map((row, d) => [<span key={'l' + d}>{days[d]}</span>, ...row.map((v, h) => <i key={d + '-' + h} title={v === null ? `${days[d]} ${h}:00 – brak pomiarów` : `${days[d]} ${h}:00 – dostępny w ${pct(v)} pomiarów`}
      style={v === null ? undefined : { background: `color-mix(in srgb, var(--green) ${Math.round(15 + v * 85)}%, var(--red-soft))`, borderColor: 'transparent' }} />)])}
  </div>
}

export function Copy({ text }: { text: string }) {
  const toast = useToast()
  return <button className="ghost sm" title="Kopiuj" onClick={() => { navigator.clipboard?.writeText(text); toast('Skopiowano') }}>kopiuj</button>
}
