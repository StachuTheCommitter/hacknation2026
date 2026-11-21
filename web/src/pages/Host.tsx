import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api, qs, useApi } from '../api'
import { Breakdown, Cat, ChangeType, Conf, Copy, Empty, FStatus, Heatmap, Labels, Modal, Ms, Panel, Score, Sev, State, Top, ago, catLabel, dt, pct, useAuth, useToast } from '../ui'
import { TLSCell } from './Assets'

export default function Host() {
  const { ip = '' } = useParams()
  const { data: d, error, reload } = useApi<any>('/hosts/' + ip)
  const { can } = useAuth()
  const toast = useToast()
  if (error) return <><Top title={ip} crumbs={<Link to="/assets/hosts">Hosty</Link>} /><div className="page"><Empty title="Nie znaleziono hosta" /></div></>
  if (!d) return <><Top title={ip} crumbs={<Link to="/assets/hosts">Hosty</Link>} /><div className="page muted">Wczytywanie…</div></>
  const h = d.host
  const retry = async () => {
    try { const r = await api('/retry', { body: { ip } }); toast('Uruchomiono ponowny pomiar'); window.location.href = '/scans/runs/' + r.id } catch (e: any) { toast(e.message, true) }
  }
  const push = async () => {
    try { await api('/findings/push', { body: { keys: [ip] } }); toast('Wysłano do DefectDojo'); reload() } catch (e: any) { toast(e.message, true) }
  }
  return <>
    <Top title={<span className="mono">{ip}</span>} crumbs={<><Link to="/assets/hosts">Hosty</Link>{h.group && <> · {h.group}</>}</>}>
      {can('scans:start') && <button onClick={retry}>Zmierz ponownie</button>}
      {can('defectdojo:push') && <button onClick={push}>Wyślij do DefectDojo</button>}
    </Top>
    <div className="page">
      <div className="row" style={{ marginBottom: 14 }}>
        <Score v={h.score} /> <State s={h.state} /> <Labels l={h.labels} />
        {h.hostnames?.map((n: string) => <span key={n} className="badge">{n}</span>)}
        {h.os && <span className="muted small">{h.os}</span>}
        <span className="muted small">pierwszy raz {dt(h.first_seen)} · ostatnio {ago(h.last_seen)}</span>
      </div>
      {h.score_breakdown?.length > 0 && <div className="why" style={{ marginTop: -6, marginBottom: 14 }}>Ocena: <Breakdown items={h.score_breakdown} /></div>}
      <div className="grid g-main">
        <div className="stack">
          {d.services?.length === 0 && <Panel><Empty title="Brak wykrytych usług" /></Panel>}
          {d.services?.map((s: any) => <ServiceBlock key={s.id} s={s} reload={reload} />)}
        </div>
        <div className="stack">
          <HostOverlay d={d} reload={reload} />
          <Availability d={d} />
          <Tags etype="host" k={ip} tags={h.tags} reload={reload} />
          <Notes etype="host" k={ip} notes={d.notes} reload={reload} />
          <Panel title="Znaleziska" pad={false}>
            {!d.findings?.length ? <Empty title="Brak znalezisk" /> : <table className="tbl compact"><tbody>{d.findings.map((f: any) =>
              <tr key={f.id} className={f.active ? '' : 'dim'}><td><Sev s={f.severity} /></td><td className="small">{f.title.replace('[ASI] ', '')}<div className="sub">{f.dd_finding_id ? `DefectDojo #${f.dd_finding_id}` : 'nie wysłano'}</div></td><td><FStatus s={f.status} /></td></tr>)}</tbody></table>}
          </Panel>
          <Panel title="Historia zmian" pad={false}>
            {!d.changes?.length ? <Empty title="Brak zmian" /> : <table className="tbl compact"><tbody>{d.changes.slice(0, 40).map((c: any) =>
              <tr key={c.id}><td className="nowrap small muted">{ago(c.at)}</td><td><ChangeType t={c.type} /><div className="small" style={{ marginTop: 2 }}>{c.summary}</div><DiffFields diff={c.diff} /></td></tr>)}</tbody></table>}
          </Panel>
          {d.override_history?.length > 0 && <Panel title="Historia edycji" pad={false}><table className="tbl compact"><tbody>{d.override_history.map((o: any, i: number) =>
            <tr key={i}><td className="small">{o.field}</td><td className="small mono">{fmt(o.old)} → {fmt(o.new)}</td><td className="small muted nowrap">{o.by}<br />{ago(o.at)}</td></tr>)}</tbody></table></Panel>}
        </div>
      </div>
    </div>
  </>
}

export function DiffFields({ diff }: { diff: any[] }) {
  if (!diff?.length) return null
  return <div className="diffval" style={{ marginTop: 3 }}>{diff.slice(0, 6).map((f, i) => <div key={i}><span className="muted">{f.field}:</span> {f.old !== null && f.old !== '' && <span className="old">{fmt(f.old)}</span>} {f.new !== null && f.new !== '' && <span className="new">{fmt(f.new)}</span>}</div>)}</div>
}

export function fmt(v: any): string {
  if (v === null || v === undefined || v === '') return '∅'
  if (Array.isArray(v)) return v.join(', ') || '∅'
  if (typeof v === 'object') return JSON.stringify(v)
  return String(v)
}

// ---------- usługa ----------
function ServiceBlock({ s, reload }: { s: any; reload: () => void }) {
  const ov = s.override_views || {}
  const techs = parseJ(s.techs), cats = parseJ(s.categories_full), matches = parseJ(s.matches)
  const tls = parseObj(s.tls)
  return <section className="panel" style={{ opacity: s.state === 'INACTIVE' ? 0.6 : 1 }}>
    <div className="ph">
      <h2 className="mono" style={{ margin: 0 }}>{s.port}<span className="faint">/{s.proto}</span></h2>
      <span className="nowrap"><EditField etype="service" k={s.key} field="service_name" value={s.service} ov={ov.service_name} placeholder="usługa?" /></span>
      <span className="nowrap"><b><EditField etype="service" k={s.key} field="product" value={s.product} ov={ov.product} placeholder="produkt" /></b> <EditField etype="service" k={s.key} field="version" value={s.version} ov={ov.version} placeholder="wersja" /></span>
      <span className="muted small">{s.extrainfo}</span>
      <div className="spacer" />
      <span className="small muted" title={s.nmap_method === 'table' ? 'nmap zgadł usługę tylko z numeru portu' : `nmap: ${s.nmap_method || 'brak'} ${s.nmap_conf || ''}/10`}>pewność <Conf v={s.confidence} /></span>
      <State s={s.state} /><Labels l={s.labels} /><Score v={s.score} />
    </div>
    <div className="pb stack">
      {(cats.length > 0 || matches.length > 0 || s.score_breakdown?.length > 0) && <div>
        <div className="row tight">{cats.map((c: any) => <Cat key={c.category} c={c.category} conf={c.confidence} />)}
          {s.cpe?.map((c: string) => <span key={c} className="badge mono">{c}</span>)}</div>
        <Matches m={matches} />
        {s.score_breakdown?.length > 0 && <div className="why" style={{ marginTop: 4 }}>Ocena: <Breakdown items={parseJ(s.score_breakdown)} /></div>}
      </div>}
      {techs.length > 0 && <TechTable techs={techs} />}
      {tls && <div className="small">TLS: {tls.subject_cn} · {tls.issuer} · <TLSCell t={tls} /></div>}
      {s.web?.map((w: any) => <WebBlock key={w.id} w={w} reload={reload} />)}
      <RawButton etype="service" k={s.key} />
    </div>
  </section>
}

function parseJ(v: any) { if (!v) return []; return typeof v === 'string' ? JSON.parse(v) : v }
function parseObj(v: any) { if (!v || v === 'null') return null; const o = typeof v === 'string' ? JSON.parse(v) : v; return o && typeof o === 'object' && Object.keys(o).length ? o : null }

function Matches({ m }: { m: any[] }) {
  if (!m?.length) return null
  return <div style={{ marginTop: 6 }}>{m.map((x: any) => <div key={x.sig_id} className="small"><span className="badge solid">{x.sig_id}</span> <span className="why">{(x.evidence || []).join(' · ')}</span></div>)}</div>
}

function TechTable({ techs }: { techs: any[] }) {
  const [open, setOpen] = useState<string | null>(null)
  return <table className="tbl compact">
    <thead><tr><th>Technologia</th><th>Wersja</th><th>Kategoria</th><th className="num">Pewność</th><th>Dowody</th></tr></thead>
    <tbody>{techs.map(t => <tr key={t.name}>
      <td><b>{t.name}</b></td><td className="mono small">{t.version || <span className="faint">—</span>}</td><td className="small muted">{catLabel[t.category] || t.category}</td>
      <td className="num"><Conf v={t.confidence} /></td>
      <td className="small"><button className="ghost sm" onClick={() => setOpen(open === t.name ? null : t.name)}>{(t.evidence || []).length} {open === t.name ? '▴' : '▾'}</button>
        {open === t.name && <div className="why">{(t.evidence || []).map((e: any, i: number) => <div key={i}>{e.source}: {e.detail} <span className="faint">(waga {pct(e.weight)})</span></div>)}</div>}</td>
    </tr>)}</tbody>
  </table>
}

function WebBlock({ w }: { w: any; reload: () => void }) {
  const techs = parseJ(w.techs), cats = parseJ(w.categories), matches = parseJ(w.matches), cookies = parseJ(w.cookies), tls = parseObj(w.tls)
  const ov = w.overrides || {}
  return <div style={{ borderTop: '1px solid var(--line)', paddingTop: 10 }}>
    <div className="row">
      <a className="mono" href={w.url} target="_blank" rel="noreferrer noopener">{w.url}</a>
      <span className={'badge ' + (w.status >= 400 ? '' : 'green')}>{w.status}</span>
      <b><EditField etype="http" k={w.key} field="title" value={w.title} ov={ov.title} /></b>
      <div className="spacer" /><Score v={w.score} />
    </div>
    {w.final_url && w.final_url !== w.url && <div className="small muted">→ {w.final_url}</div>}
    <div className="row tight" style={{ marginTop: 6 }}>{cats.filter((c: any) => c.confidence >= 0.45).map((c: any) => <Cat key={c.category} c={c.category} conf={c.confidence} />)}</div>
    <Matches m={matches} />
    {w.score_breakdown && parseJ(w.score_breakdown).length > 0 && <div className="why" style={{ marginTop: 4 }}>Ocena: <Breakdown items={parseJ(w.score_breakdown)} /></div>}
    <div className="grid g2" style={{ marginTop: 10 }}>
      <dl className="kv">
        <dt>Serwer</dt><dd>{w.server || '—'}{w.powered_by && <> · {w.powered_by}</>}</dd>
        <dt>Nagłówki</dt><dd className="small mono">{w.header_names?.join(', ')}</dd>
        <dt>Cookies</dt><dd className="small">{cookies.length ? cookies.map((c: any) => <div key={c.name}><span className="mono">{c.name}</span> <span className="faint">{[c.secure && 'Secure', c.httponly && 'HttpOnly', c.samesite && 'SameSite=' + c.samesite].filter(Boolean).join(' ') || 'bez flag'}</span></div>) : '—'}</dd>
        <dt>Favicona (mmh3)</dt><dd className="mono small">{w.favicon_mmh3 || '—'}</dd>
      </dl>
      <dl className="kv">
        <dt>TLS</dt><dd>{tls ? <><TLSCell t={tls} /><div className="small">{tls.subject_cn}{tls.san?.length ? ` (+${tls.san.length} SAN)` : ''}<br /><span className="muted">{tls.issuer}</span><br />ważny do {dt(tls.not_after)}</div></> : '—'}</dd>
        <dt>Czas odpowiedzi</dt><dd><Ms v={w.response_ms} /></dd>
        <dt>Widziany</dt><dd className="small">{dt(w.first_seen)} – {ago(w.last_seen)}</dd>
      </dl>
    </div>
    {techs.length > 0 && <div style={{ marginTop: 10 }}><TechTable techs={techs} /></div>}
    <div className="row" style={{ marginTop: 8 }}><RawButton etype="http" k={w.key} /><span className="faint small mono">{w.key}</span><Copy text={w.key} /></div>
  </div>
}

function RawButton({ etype, k }: { etype: string; k: string }) {
  const { can } = useAuth()
  const [raw, setRaw] = useState<any>(null)
  if (!can('sensitive:read')) return <span className="faint small" title="Wymaga uprawnienia sensitive:read">dane surowe ukryte (wymagane uprawnienie)</span>
  return <>
    <button className="sm" onClick={async () => setRaw(await api('/raw' + qs({ entity_type: etype, key: k })))}>Dane surowe</button>
    {raw && <Modal title="Dane surowe (odszyfrowane)" onClose={() => setRaw(null)} wide>
      <div className="notice warn" style={{ marginBottom: 10 }}>Dane wrażliwe – przechowywane w bazie jako szyfrogram AES-256-GCM. Odczyt został zapisany w dzienniku audytu.</div>
      {raw.paths?.length > 0 && <><h3>Sprawdzone ścieżki</h3><table className="tbl compact" style={{ marginBottom: 12 }}><tbody>{raw.paths.map((p: any) =>
        <tr key={p.path}><td className="mono">{p.path}</td><td>{p.status}</td><td className="small">{p.soft404 ? <span className="faint">soft-404</span> : p.title}</td><td className="small">{p.pattern_match !== undefined && (p.pattern_match ? <span className="badge red">wzorzec pasuje</span> : 'brak')}</td></tr>)}</tbody></table></>}
      <pre className="pre">{JSON.stringify({ ...raw, paths: undefined }, null, 2)}</pre>
    </Modal>}
  </>
}

// ---------- warstwa nadpisań ----------
export function EditField({ etype, k, field, value, ov, placeholder }: { etype: string; k: string; field: string; value: any; ov?: any; placeholder?: string }) {
  const { can } = useAuth()
  const toast = useToast()
  const [editing, setEditing] = useState(false)
  const shown = ov ? ov.value : value
  const [v, setV] = useState(fmtEdit(shown))
  const [cur, setCur] = useState<any>(ov)
  const [val, setVal] = useState(shown)
  const save = async () => {
    try {
      let out: any = v
      if (field === 'priority') out = Number(v)
      if (field === 'technologies' || field === 'category') out = v.split(',').map(s => s.trim()).filter(Boolean)
      await api('/overrides', { method: 'PUT', body: { entity_type: etype, key: k, field, value: out } })
      setVal(out); setCur({ value: out, scanner_value: value, conflict: false }); setEditing(false); toast('Zapisano – wartość przetrwa kolejne skany')
    } catch (e: any) { toast(e.message, true) }
  }
  const revert = async () => {
    await api('/overrides' + qs({ entity_type: etype, key: k, field }), { method: 'DELETE' })
    setVal(value); setCur(null); setV(fmtEdit(value)); setEditing(false); toast('Przywrócono wartość ze skanera')
  }
  const confirm = async () => {
    await api('/overrides', { method: 'PUT', body: { entity_type: etype, key: k, field, confirm: true } })
    setCur({ ...cur, conflict: false }); toast('Potwierdzono wartość analityka')
  }
  if (!can('results:update')) return <span>{fmtShow(val) || <span className="faint">{placeholder || '—'}</span>}</span>
  if (editing) return <span className="row tight" style={{ display: 'inline-flex' }}>
    <input autoFocus value={v} onChange={e => setV(e.target.value)} onKeyDown={e => { if (e.key === 'Enter') save(); if (e.key === 'Escape') setEditing(false) }} style={{ minHeight: 24, height: 24, width: 180 }} />
    <button className="sm primary" onClick={save}>Zapisz</button>{cur && <button className="sm" onClick={revert} title="Usuń nadpisanie">Skaner</button>}<button className="sm ghost" onClick={() => setEditing(false)}>Anuluj</button>
  </span>
  return <span>
    <span className="editable" title={cur ? `Ustawione ręcznie przez ${cur.by || 'analityka'}; skaner: ${fmtShow(cur.scanner_value) || '∅'}` : 'Kliknij, aby edytować'} onClick={() => { setV(fmtEdit(val)); setEditing(true) }}>
      {fmtShow(val) || <span className="faint">{placeholder || 'ustaw'}</span>}</span>
    {cur && <span className="badge" style={{ marginLeft: 4 }}>ręcznie</span>}
    {cur?.conflict && <span className="conflict" title={`Skaner widzi teraz: ${fmtShow(cur.scanner_value)} (przy edycji: ${fmtShow(cur.scanner_value_at_edit)})`}> ⚠
      <button className="sm ghost" onClick={revert}>przyjmij skaner</button><button className="sm ghost" onClick={confirm}>zostaw moją</button></span>}
  </span>
}
function fmtEdit(v: any) { return Array.isArray(v) ? v.join(', ') : v === undefined || v === null ? '' : String(v) }
function fmtShow(v: any) { return Array.isArray(v) ? v.join(', ') : v === undefined || v === null ? '' : String(v) }

function HostOverlay({ d, reload }: { d: any; reload: () => void }) {
  const ip = d.host.ip, ov = d.overrides || {}
  const { can } = useAuth()
  const toast = useToast()
  const muted = ov.muted?.value === true
  const toggleMute = async () => {
    if (muted) await api('/overrides' + qs({ entity_type: 'host', key: ip, field: 'muted' }), { method: 'DELETE' })
    else await api('/overrides', { method: 'PUT', body: { entity_type: 'host', key: ip, field: 'muted', value: true } })
    toast(muted ? 'Wyciszenie zdjęte' : 'Host wyciszony'); reload()
  }
  return <Panel title="Opis analityka" actions={can('results:update') && <button className="sm" onClick={toggleMute}>{muted ? 'Zdejmij wyciszenie' : 'Wycisz'}</button>}>
    <dl className="kv">
      <dt>Opis</dt><dd><EditField etype="host" k={ip} field="description" value="" ov={ov.description} placeholder="dodaj opis" /></dd>
      <dt>Właściciel</dt><dd><EditField etype="host" k={ip} field="owner" value="" ov={ov.owner} placeholder="np. Instytut Informatyki" /></dd>
      <dt>Kategoria zasobu</dt><dd><EditField etype="host" k={ip} field="category" value={d.host.categories} ov={ov.category} /></dd>
      <dt>Cykl życia</dt><dd><EditField etype="host" k={ip} field="lifecycle" value="" ov={ov.lifecycle} placeholder="produkcja / test / wycofany" /></dd>
      <dt>Priorytet (0–100)</dt><dd><EditField etype="host" k={ip} field="priority" value={d.host.score} ov={ov.priority} /></dd>
      <dt>System</dt><dd><EditField etype="host" k={ip} field="os" value={d.host.os} ov={ov.os} /></dd>
    </dl>
    {muted && <div className="notice warn" style={{ marginTop: 10 }}>Host wyciszony – nie trafia do kolejki „do przejrzenia”.</div>}
    <div className="hint" style={{ marginTop: 8 }}>Edycje są zapisywane osobno od danych skanera i nie są nadpisywane przez kolejne skany. ⚠ oznacza, że skaner widzi teraz inną wartość niż w chwili edycji.</div>
  </Panel>
}

function Availability({ d }: { d: any }) {
  const tl = [...(d.timeline || [])].reverse().slice(-60)
  const per = d.periodicity ? (typeof d.periodicity === 'string' ? JSON.parse(d.periodicity) : d.periodicity) : {}
  return <Panel title="Dostępność">
    {tl.length === 0 ? <span className="muted">Brak historii pomiarów.</span> : <>
      <div className="strip" title="ostatnie pomiary (od lewej najstarsze)">{tl.map((p: any, i: number) => <i key={i} className={p.up ? (p.retry ? 'retry' : '') : 'down'} title={`${dt(p.at)} – ${p.up ? (p.retry ? 'odpowiedział dopiero przy powtórce' : 'odpowiada') : 'brak odpowiedzi'}`} />)}</div>
      <dl className="kv" style={{ marginTop: 10 }}>
        <dt>Kolejne braki</dt><dd>{d.consecutive_misses}</dd>
        <dt>Widziany w</dt><dd>{d.total_seen} przebiegach</dd>
        <dt>Flap rate</dt><dd>{(d.flap_score || 0).toFixed(2)} {d.flap_score >= 0.4 && <span className="badge amber">niestabilny</span>}</dd>
        {per.label && <><dt>Okresowość</dt><dd>{per.label.toLowerCase()}</dd></>}
      </dl>
      <h3 style={{ marginTop: 12 }}>Pora dnia × dzień tygodnia</h3>
      <Heatmap data={d.heatmap} />
    </>}
  </Panel>
}

export function Tags({ etype, k, tags, reload }: { etype: string; k: string; tags: string[]; reload: () => void }) {
  const { can } = useAuth()
  const [v, setV] = useState('')
  const add = async () => { if (!v.trim()) return; await api('/tags', { body: { entity_type: etype, keys: [k], tag: v } }); setV(''); reload() }
  const rm = async (t: string) => { await api('/tags', { body: { entity_type: etype, keys: [k], tag: t, remove: true } }); reload() }
  return <Panel title="Tagi">
    <div className="row tight">{tags?.map(t => <span key={t} className="tag">{t}{can('results:update') && <a style={{ marginLeft: 4, cursor: 'pointer' }} onClick={() => rm(t)}>×</a>}</span>)}
      {!tags?.length && <span className="faint small">brak</span>}</div>
    {can('results:update') && <div className="row" style={{ marginTop: 8 }}><input value={v} onChange={e => setV(e.target.value)} onKeyDown={e => e.key === 'Enter' && add()} placeholder="nowy tag" style={{ flex: 1 }} /><button className="sm" onClick={add}>Dodaj</button></div>}
  </Panel>
}

function Notes({ etype, k, notes, reload }: { etype: string; k: string; notes: any[]; reload: () => void }) {
  const { can } = useAuth()
  const [v, setV] = useState('')
  const add = async () => { await api('/notes', { body: { entity_type: etype, key: k, body: v } }); setV(''); reload() }
  return <Panel title="Notatki">
    {notes?.map(n => <div key={n.id} style={{ marginBottom: 8 }}><div className="small muted">{n.created_by} · {ago(n.created_at)}</div><div style={{ whiteSpace: 'pre-wrap' }}>{n.body}</div></div>)}
    {!notes?.length && <div className="faint small">Brak notatek. Notatki są szyfrowane w bazie.</div>}
    {can('results:update') && <><textarea rows={2} value={v} onChange={e => setV(e.target.value)} placeholder="Dodaj notatkę…" style={{ marginTop: 6 }} />
      <div className="row" style={{ marginTop: 6 }}><div className="spacer" /><button className="sm" disabled={!v.trim()} onClick={add}>Dodaj notatkę</button></div></>}
  </Panel>
}


