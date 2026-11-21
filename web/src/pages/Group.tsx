import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api, useApi } from '../api'
import { Empty, ErrorNote, Modal, Panel, State, Top, ago, num, useAuth, useToast } from '../ui'
import { Estimate, GroupForm, StartRun } from './Scans'

const DAYS = ['pn', 'wt', 'śr', 'cz', 'pt', 'sb', 'nd']
const hm = (m: number) => `${String(Math.floor(m / 60)).padStart(2, '0')}:${String(m % 60).padStart(2, '0')}`
const parseHM = (s: string) => { const [h, m] = s.split(':').map(Number); return (h || 0) * 60 + (m || 0) }

export default function Group() {
  const { id = '' } = useParams()
  const { data: g, reload } = useApi<any>('/target-groups/' + id)
  const targets = useApi<any[]>('/targets?group_id=' + id)
  const windows = useApi<any[]>('/windows?group_id=' + id)
  const schedules = useApi<any[]>('/schedules?group_id=' + id)
  const runs = useApi<any[]>('/runs?limit=10&source=scanner&group_id=' + id)
  const { can } = useAuth()
  const toast = useToast()
  const nav = useNavigate()
  const [edit, setEdit] = useState(false)
  const [start, setStart] = useState(false)
  const [est, setEst] = useState<any>(null)
  useEffect(() => { if (g) api('/estimate', { body: { group_id: id } }).then(setEst).catch(() => {}) }, [g?.id, windows.data?.length])
  if (!g) return <><Top title="Grupa" /><div className="page muted">Wczytywanie…</div></>
  const reloadAll = () => { reload(); targets.reload(); windows.reload(); schedules.reload() }
  const del = async () => { if (!confirm('Usunąć grupę i jej cele?')) return; await api('/target-groups/' + id, { method: 'DELETE' }); nav('/scans?tab=groups') }
  return <>
    <Top title={g.name} crumbs={<><Link to="/scans?tab=groups">Grupy celów</Link></>}>
      {can('targets:update') && <button onClick={() => setEdit(true)}>Edytuj</button>}
      {can('targets:delete') && <button className="danger" onClick={del}>Usuń</button>}
      {can('scans:start') && <button className="primary" onClick={() => setStart(true)}>Uruchom skan</button>}
    </Top>
    <div className="page stack">
      <div className="kpis">
        <div className="kpi"><div className="v">{num(g.addresses)}</div><div className="l">adresów w celach</div></div>
        <div className="kpi"><div className="v">{g.hosts}</div><div className="l">aktywne hosty</div></div>
        <div className="kpi"><div className="v">{num(g.rate_pps)}</div><div className="l">budżet pps (wspólny)</div></div>
        <div className="kpi"><div className="v">{g.http_rps}</div><div className="l">żądań HTTP/s</div></div>
        <div className="kpi"><div className="v">{g.window?.has_windows ? (g.window.open ? 'otwarte' : 'zamknięte') : 'zawsze'}</div><div className="l">okno czasowe{g.window?.next_open && !g.window.open ? ' · otwarcie ' + new Date(g.window.next_open).toLocaleString('pl-PL', { weekday: 'short', hour: '2-digit', minute: '2-digit' }) : ''}</div></div>
      </div>
      {est && <Estimate e={est} />}
      <div className="grid g2">
        <Targets gid={id} list={targets.data || []} reload={reloadAll} />
        <div className="stack">
          <Windows gid={id} list={windows.data || []} reload={reloadAll} />
          <Schedules gid={id} list={schedules.data || []} reload={reloadAll} />
          <Panel title="Ostatnie przebiegi" pad={false}>
            {!runs.data?.length ? <Empty title="Brak" /> : <table className="tbl compact"><tbody>{runs.data.map(r =>
              <tr key={r.id} className="click" onClick={() => nav('/scans/runs/' + r.id)}><td><State s={r.status} /></td><td className="small">{r.mode}</td><td className="small muted">{ago(r.created_at)}</td></tr>)}</tbody></table>}
          </Panel>
        </div>
      </div>
    </div>
    {edit && <GroupForm group={g} onClose={() => { setEdit(false); reload(); toast('Zapisano') }} />}
    {start && <StartRun groupId={id} onClose={() => setStart(false)} />}
  </>
}

function Targets({ gid, list, reload }: { gid: string; list: any[]; reload: () => void }) {
  const { can } = useAuth()
  const toast = useToast()
  const [text, setText] = useState('')
  const [check, setCheck] = useState<any>(null)
  const [rep, setRep] = useState<any>(null)
  const [err, setErr] = useState<any>(null)
  useEffect(() => {
    if (!text.trim()) { setCheck(null); return }
    const t = setTimeout(() => api('/targets/validate', { body: { text } }).then(setCheck).catch(() => {}), 400)
    return () => clearTimeout(t)
  }, [text])
  const add = async () => {
    try { const r = await api('/targets', { body: { group_id: gid, text } }); setRep(r); setText(''); reload(); toast(`Dodano ${r.accepted} celów`) } catch (e) { setErr(e) }
  }
  const upload = async (f: File) => {
    const fd = new FormData(); fd.append('file', f); fd.append('group_id', gid)
    try { const r = await api('/targets/import', { form: fd }); setRep(r); reload() } catch (e) { setErr(e) }
  }
  const del = async (id: string) => { await api('/targets/' + id, { method: 'DELETE' }); reload() }
  const toggle = async (t: any) => { await api('/targets/' + t.id, { method: 'PATCH', body: { enabled: !t.enabled, tags: t.tags } }); reload() }
  return <Panel title={`Cele (${list.length})`} actions={can('targets:create') && <label className="btn sm" style={{ height: 24 }}>Import CSV / JSON / TXT<input type="file" hidden accept=".csv,.json,.txt" onChange={e => e.target.files?.[0] && upload(e.target.files[0])} /></label>}>
    {can('targets:create') && <div style={{ marginBottom: 12 }}>
      <textarea className="code" rows={3} value={text} onChange={e => setText(e.target.value)} placeholder={'10.77.1.0/24\n10.77.2.10-10.77.2.50\nportal.lab.local'} />
      {check && <div className="small" style={{ marginTop: 4 }}>{check.items.map((i: any) => <div key={i.value} className={i.error ? 'conflict' : 'muted'}>{i.value}: {i.error || `${i.kind}, ${num(i.addresses)} adresów`}</div>)}</div>}
      <div className="row" style={{ marginTop: 6 }}><span className="hint">IP, CIDR (do /16), zakres a-b lub domena; wiele w osobnych liniach</span><div className="spacer" /><button className="primary sm" disabled={!text.trim()} onClick={add}>Dodaj cele</button></div>
      <ErrorNote e={err} />
      {rep && <div className={'notice ' + (rep.rejected?.length ? 'warn' : 'ok')} style={{ marginTop: 6 }}>Przyjęto {rep.accepted}, duplikaty {rep.duplicates}, odrzucono {rep.rejected?.length || 0}
        {rep.rejected?.map((r: any) => <div key={r.value}>{r.value}: {r.reason}</div>)}{rep.notes?.map((n: string) => <div key={n}>{n}</div>)}</div>}
    </div>}
    {!list.length ? <Empty title="Brak celów" /> : <table className="tbl compact"><tbody>{list.map(t => <tr key={t.id} className={t.enabled ? '' : 'dim'}>
      <td className="mono">{t.value}</td><td className="small muted">{t.kind}</td><td className="num small">{num(t.addresses)}</td><td className="small muted">{t.source}</td>
      <td className="right nowrap">{can('targets:update') && <button className="ghost sm" onClick={() => toggle(t)}>{t.enabled ? 'wyłącz' : 'włącz'}</button>}{can('targets:delete') && <button className="ghost sm danger" onClick={() => del(t.id)}>usuń</button>}</td>
    </tr>)}</tbody></table>}
  </Panel>
}

function Windows({ gid, list, reload }: { gid: string; list: any[]; reload: () => void }) {
  const { can } = useAuth()
  const [edit, setEdit] = useState<any>(null)
  const del = async (id: string) => { await api('/windows/' + id, { method: 'DELETE' }); reload() }
  return <Panel title="Okna czasowe" actions={can('config:create') && <button className="sm" onClick={() => setEdit({ group_id: gid, days_mask: 127, start_min: 22 * 60, end_min: 6 * 60, kind: 'full', rate_factor: 1 })}>Dodaj okno</button>}>
    {!list.length ? <div className="muted small">Brak okien – skanowanie dozwolone zawsze (zgodnie z ustawieniem grupy).</div> :
      <WeekGrid list={list} onPick={w => can('config:update') && setEdit(w)} />}
    {list.length > 0 && <table className="tbl compact" style={{ marginTop: 10 }}><tbody>{list.map(w => <tr key={w.id}>
      <td>{DAYS.filter((_, i) => w.days_mask & (1 << i)).join(' ')}</td><td className="mono">{hm(w.start_min)}–{hm(w.end_min)}</td>
      <td>{w.kind === 'full' ? <span className="badge green">pełne</span> : <span className="badge violet">niskie tempo ({Math.round(w.rate_factor * 100)}%)</span>}</td>
      <td className="right">{can('config:update') && <button className="ghost sm" onClick={() => setEdit(w)}>edytuj</button>}{can('config:delete') && <button className="ghost sm danger" onClick={() => del(w.id)}>usuń</button>}</td>
    </tr>)}</tbody></table>}
    <div className="hint" style={{ marginTop: 8 }}>Po zamknięciu okna działające zadania są przerywane, a skan wraca od miejsca przerwania w kolejnym oknie. Okno „niskie tempo” pozwala w dzień tylko sprawdzić dostępność hostów.</div>
    {edit && <WindowForm w={edit} onClose={() => { setEdit(null); reload() }} />}
  </Panel>
}

function WeekGrid({ list, onPick }: { list: any[]; onPick: (w: any) => void }) {
  const cells = (d: number) => {
    const out: (any | null)[] = Array(24).fill(null)
    for (const w of list) {
      for (let h = 0; h < 24; h++) {
        const m = h * 60 + 30
        const inToday = w.end_min > w.start_min ? (m >= w.start_min && m < w.end_min) : (m >= w.start_min)
        const inFromYesterday = w.end_min <= w.start_min && m < w.end_min
        if ((inToday && w.days_mask & (1 << d)) || (inFromYesterday && w.days_mask & (1 << ((d + 6) % 7)))) out[h] = out[h]?.kind === 'full' ? out[h] : w
      }
    }
    return out
  }
  return <div className="heat">
    <span />{Array.from({ length: 24 }, (_, h) => <span key={h} style={{ textAlign: 'center' }}>{h % 6 === 0 ? h : ''}</span>)}
    {DAYS.map((d, i) => [<span key={d}>{d}</span>, ...cells(i).map((w, h) => <i key={d + h} onClick={() => w && onPick(w)} title={w ? `${d} ${h}:00 – ${w.kind === 'full' ? 'okno pełne' : 'niskie tempo'}` : `${d} ${h}:00 – poza oknem`}
      style={w ? { background: w.kind === 'full' ? 'var(--accent)' : 'var(--violet)', opacity: w.kind === 'full' ? 0.85 : 0.6, borderColor: 'transparent', cursor: 'pointer' } : undefined} />)])}
  </div>
}

function WindowForm({ w, onClose }: { w: any; onClose: () => void }) {
  const [f, setF] = useState({ ...w, start: hm(w.start_min), end: hm(w.end_min) })
  const [err, setErr] = useState<any>(null)
  const save = async () => {
    const body = { group_id: f.group_id, days_mask: f.days_mask, start_min: parseHM(f.start), end_min: parseHM(f.end), kind: f.kind, rate_factor: +f.rate_factor, mode: f.kind === 'low_impact' ? 'liveness' : '' }
    try { w.id ? await api('/windows/' + w.id, { method: 'PUT', body }) : await api('/windows', { body }); onClose() } catch (e) { setErr(e) }
  }
  return <Modal title={w.id ? 'Edycja okna' : 'Nowe okno czasowe'} onClose={onClose} footer={<><button onClick={onClose}>Anuluj</button><button className="primary" onClick={save}>Zapisz</button></>}>
    <div className="stack">
      <div className="row">{DAYS.map((d, i) => <label key={d} className="check"><input type="checkbox" checked={!!(f.days_mask & (1 << i))} onChange={e => setF({ ...f, days_mask: e.target.checked ? f.days_mask | (1 << i) : f.days_mask & ~(1 << i) })} />{d}</label>)}</div>
      <div className="form-grid">
        <label className="f"><span>Od</span><input type="time" value={f.start} onChange={e => setF({ ...f, start: e.target.value })} /></label>
        <label className="f"><span>Do (może być po północy)</span><input type="time" value={f.end} onChange={e => setF({ ...f, end: e.target.value })} /></label>
        <label className="f"><span>Rodzaj</span><select value={f.kind} onChange={e => setF({ ...f, kind: e.target.value, rate_factor: e.target.value === 'full' ? 1 : 0.1 })}><option value="full">pełne</option><option value="low_impact">niskie tempo (sprawdzanie dostępności)</option></select></label>
        {f.kind === 'low_impact' && <label className="f"><span>Część budżetu</span><input type="number" step="0.05" min="0.05" max="1" value={f.rate_factor} onChange={e => setF({ ...f, rate_factor: e.target.value })} /></label>}
      </div>
      <ErrorNote e={err} />
    </div>
  </Modal>
}

function Schedules({ gid, list, reload }: { gid: string; list: any[]; reload: () => void }) {
  const { can } = useAuth()
  const { data: profiles } = useApi<any[]>('/profiles')
  const [f, setF] = useState<any>(null)
  const [err, setErr] = useState<any>(null)
  const save = async () => {
    try { f.id ? await api('/schedules/' + f.id, { method: 'PUT', body: f }) : await api('/schedules', { body: f }); setF(null); reload() } catch (e) { setErr(e) }
  }
  const del = async (id: string) => { await api('/schedules/' + id, { method: 'DELETE' }); reload() }
  return <Panel title="Harmonogram" actions={can('config:create') && <button className="sm" onClick={() => setF({ group_id: gid, cron: '15 22 * * *', mode: 'differential', overlap_policy: 'skip', enabled: true, profile_id: '' })}>Dodaj</button>}>
    {!list.length ? <div className="muted small">Brak harmonogramu – skany tylko ręcznie.</div> : <table className="tbl compact"><tbody>{list.map(s => <tr key={s.id} className={s.enabled ? '' : 'dim'}>
      <td className="mono">{s.cron}</td><td className="small">{s.mode}</td><td className="small muted">następne: {s.next_runs?.[0]}</td><td className="small muted">nakładanie: {s.overlap_policy}</td>
      <td className="right">{can('config:update') && <button className="ghost sm" onClick={() => setF(s)}>edytuj</button>}{can('config:delete') && <button className="ghost sm danger" onClick={() => del(s.id)}>usuń</button>}</td></tr>)}</tbody></table>}
    {f && <Modal title="Harmonogram" onClose={() => setF(null)} footer={<><button onClick={() => setF(null)}>Anuluj</button><button className="primary" onClick={save}>Zapisz</button></>}>
      <div className="stack">
        <label className="f"><span>CRON (minuta godzina dzień miesiąc dzień-tygodnia, strefa grupy)</span><input className="mono" value={f.cron} onChange={e => setF({ ...f, cron: e.target.value })} /></label>
        <div className="hint">Przykłady: <code>15 22 * * *</code> codziennie 22:15 · <code>40 1 * * 6</code> w soboty 1:40 · <code>@weekly</code></div>
        <div className="form-grid">
          <label className="f"><span>Tryb</span><select value={f.mode} onChange={e => setF({ ...f, mode: e.target.value })}><option value="baseline">baseline</option><option value="differential">differential</option><option value="liveness">liveness</option></select></label>
          <label className="f"><span>Gdy poprzedni wciąż trwa</span><select value={f.overlap_policy} onChange={e => setF({ ...f, overlap_policy: e.target.value })}><option value="skip">pomiń</option><option value="supersede">zastąp</option><option value="queue">dołącz do kolejki</option></select></label>
          <label className="f"><span>Profil</span><select value={f.profile_id} onChange={e => setF({ ...f, profile_id: e.target.value })}><option value="">profil grupy</option>{profiles?.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}</select></label>
        </div>
        <label className="check"><input type="checkbox" checked={f.enabled} onChange={e => setF({ ...f, enabled: e.target.checked })} />aktywny</label>
        <ErrorNote e={err} />
      </div>
    </Modal>}
  </Panel>
}
