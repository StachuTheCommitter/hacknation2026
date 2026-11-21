import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { api, useApi, useEvents } from '../api'
import { Empty, ErrorNote, Modal, Panel, State, Tabs, Top, ago, dur, num, pct, useAuth, useToast } from '../ui'
import Profiles from './Profiles'

export default function Scans() {
  const [sp, setSp] = useSearchParams()
  const tab = sp.get('tab') || 'runs'
  const { can } = useAuth()
  const [start, setStart] = useState(false)
  const [newGroup, setNewGroup] = useState(false)
  return <>
    <Top title="Skany">
      {can('targets:create') && <button onClick={() => setNewGroup(true)}>Nowa grupa celów</button>}
      {can('scans:start') && <button className="primary" onClick={() => setStart(true)}>Uruchom skan</button>}
    </Top>
    <div className="page">
      <Tabs items={[['runs', 'Przebiegi'], ['groups', 'Grupy celów'], ['profiles', 'Profile skanu'], ['workers', 'Workery']]} value={tab} onChange={t => setSp({ tab: t })} />
      {tab === 'runs' && <Runs />}
      {tab === 'groups' && <Groups />}
      {tab === 'profiles' && <Profiles />}
      {tab === 'workers' && <Workers />}
    </div>
    {start && <StartRun onClose={() => setStart(false)} />}
    {newGroup && <GroupForm onClose={() => setNewGroup(false)} />}
  </>
}

function Runs() {
  const [src, setSrc] = useState('scanner')
  const { data, reload } = useApi<any[]>('/runs?limit=150' + (src ? '&source=' + src : ''))
  useEvents(['run', 'task'], reload, 1200)
  const nav = useNavigate()
  return <div className="stack">
    <div className="row"><label className="check"><input type="checkbox" checked={src === ''} onChange={e => setSrc(e.target.checked ? '' : 'scanner')} />pokaż też importy i formularz</label></div>
    <Panel pad={false}>
      {!data?.length ? <Empty title="Brak przebiegów">Uruchom pierwszy skan przyciskiem „Uruchom skan”.</Empty> :
        <table className="tbl">
          <thead><tr><th>Grupa</th><th>Tryb</th><th>Stan</th><th style={{ width: '28%' }}>Postęp</th><th className="num">Hosty</th><th className="num">Nowe</th><th className="num">Zmienione</th><th>Start</th><th>Czas</th></tr></thead>
          <tbody>{data.map(r => {
            const p = r.status === 'COMPLETED' ? 1 : r.total_addresses ? r.done_addresses / r.total_addresses : 0
            const sec = r.finished_at && r.started_at ? (new Date(r.finished_at).getTime() - new Date(r.started_at).getTime()) / 1000 : null
            return <tr key={r.id} className="click" onClick={() => nav('/scans/runs/' + r.id)}>
              <td><b>{r.group_name || '—'}</b>{r.source !== 'scanner' && <div className="sub">{r.source}: {r.note}</div>}</td>
              <td className="small">{r.mode}</td>
              <td><State s={r.status} />{r.paused_reason && <div className="sub">{r.paused_reason}</div>}</td>
              <td><div className="progress"><i style={{ width: pct(p) }} /></div><div className="sub">{num(r.done_addresses)} / {num(r.total_addresses)} adresów</div></td>
              <td className="num">{r.stats?.hosts_up ?? '—'}</td><td className="num">{r.stats?.new ?? '—'}</td><td className="num">{r.stats?.changed ?? '—'}</td>
              <td className="small muted nowrap">{ago(r.created_at)}<div>{r.created_by}</div></td>
              <td className="small nowrap">{sec !== null ? dur(sec) : r.est_seconds ? <span className="muted">~{dur(r.est_seconds)}</span> : '—'}</td>
            </tr>
          })}</tbody>
        </table>}
    </Panel>
  </div>
}

function Groups() {
  const { data } = useApi<any[]>('/target-groups')
  const nav = useNavigate()
  if (!data) return null
  if (!data.length) return <Panel><Empty title="Brak grup celów">Grupa łączy cele z budżetem ruchu, oknami czasowymi i harmonogramem.</Empty></Panel>
  return <Panel pad={false}>
    <table className="tbl">
      <thead><tr><th>Grupa</th><th className="num">Adresy</th><th className="num">Cele</th><th className="num">Aktywne hosty</th><th>Budżet</th><th>Okno</th><th>Ostatni skan</th></tr></thead>
      <tbody>{data.map(g => <tr key={g.id} className="click" onClick={() => nav('/scans/groups/' + g.id)}>
        <td><b>{g.name}</b><div className="sub">{g.description}</div></td>
        <td className="num">{num(g.addresses)}</td><td className="num">{g.targets}</td><td className="num">{g.hosts}</td>
        <td className="small">{num(g.rate_pps)} pps · {g.http_rps} req/s<div className="sub">profil: {g.profile_name || 'domyślny'}</div></td>
        <td className="small">{g.window?.has_windows ? (g.window.open ? <span className="badge green">otwarte</span> : <span className="badge amber">zamknięte</span>) : <span className="muted">bez ograniczeń</span>}</td>
        <td className="small">{g.last_run ? <><State s={g.last_run.status} /> <span className="muted">{ago(g.last_run.created_at)}</span></> : <span className="faint">—</span>}</td>
      </tr>)}</tbody>
    </table>
  </Panel>
}

export function StartRun({ onClose, groupId }: { onClose: () => void; groupId?: string }) {
  const { data: groups } = useApi<any[]>('/target-groups')
  const { data: profiles } = useApi<any[]>('/profiles')
  const [g, setG] = useState(groupId || '')
  const [p, setP] = useState('')
  const [mode, setMode] = useState('baseline')
  const [est, setEst] = useState<any>(null)
  const [err, setErr] = useState<any>(null)
  const nav = useNavigate()
  const gid = g || groups?.[0]?.id || ''
  useEffect(() => { if (gid) api('/estimate', { body: { group_id: gid, profile_id: p, mode } }).then(setEst).catch(() => setEst(null)) }, [gid, p, mode])
  const go = async () => {
    try { const r = await api('/runs', { body: { group_id: gid, profile_id: p, mode } }); nav('/scans/runs/' + r.id) } catch (e) { setErr(e) }
  }
  return <Modal title="Uruchom skan" onClose={onClose} footer={<><button onClick={onClose}>Anuluj</button><button className="primary" onClick={go} disabled={!gid}>Start</button></>}>
    <div className="stack">
      <label className="f"><span>Grupa celów</span><select value={gid} onChange={e => setG(e.target.value)}>{groups?.map(x => <option key={x.id} value={x.id}>{x.name} ({num(x.addresses)} adresów)</option>)}</select></label>
      <label className="f"><span>Profil</span><select value={p} onChange={e => setP(e.target.value)}><option value="">profil grupy</option>{profiles?.map(x => <option key={x.id} value={x.id}>{x.name} – {x.ports} portów</option>)}</select></label>
      <label className="f"><span>Tryb</span><select value={mode} onChange={e => setMode(e.target.value)}>
        <option value="baseline">pełny (baseline) – odświeża wszystko</option>
        <option value="differential">szybki (differential) – nmap -sV tylko dla nowych portów</option>
        <option value="liveness">dzienny (liveness) – lekkie sprawdzenie dostępności</option>
      </select></label>
      {est && <Estimate e={est} />}
      <ErrorNote e={err} />
    </div>
  </Modal>
}

export function Estimate({ e }: { e: any }) {
  return <div className="panel" style={{ padding: 12, background: 'var(--panel-2)' }}>
    <div className="row"><b>Szacowany czas: {dur(e.seconds)}</b><span className="muted small">{e.learned ? 'na podstawie zmierzonej prędkości' : 'teoretycznie (brak pomiarów)'}</span></div>
    <div className="small muted" style={{ marginTop: 4 }}>
      discovery {dur(e.discovery_sec)} · porty {dur(e.portscan_sec)} · usługi i WWW {dur(e.probe_sec)}<br />
      {num(e.addresses)} adresów × {e.ports} portów przy {num(e.rate_pps)} pps · ok. {num(Math.round(e.packets))} pakietów · zadania po ~{num(e.chunk_size)} adresów
      {e.finish_at && <><br />uwzględniając okna czasowe: koniec ok. {e.finish_at}{e.windows_needed > 1 && ` (${e.windows_needed} okna)`}</>}
    </div>
    {e.warning && <div className="notice warn" style={{ marginTop: 8 }}>{e.warning}</div>}
  </div>
}

export function GroupForm({ onClose, group }: { onClose: () => void; group?: any }) {
  const { data: profiles } = useApi<any[]>('/profiles')
  const [f, setF] = useState<any>(group || { name: '', description: '', rate_pps: 500, http_rps: 20, max_parallel_sweeps: 2, max_parallel_probes: 4, always_allowed: true, timezone: 'Europe/Warsaw', profile_id: '' })
  const [err, setErr] = useState<any>(null)
  const nav = useNavigate()
  const toast = useToast()
  const set = (k: string, v: any) => setF({ ...f, [k]: v })
  const save = async () => {
    try {
      const body = { ...f, rate_pps: +f.rate_pps, http_rps: +f.http_rps, max_parallel_sweeps: +f.max_parallel_sweeps, max_parallel_probes: +f.max_parallel_probes }
      const r = group ? await api('/target-groups/' + group.id, { method: 'PUT', body }) : await api('/target-groups', { body })
      toast('Zapisano grupę'); onClose(); if (!group) nav('/scans/groups/' + r.id); else window.location.reload()
    } catch (e) { setErr(e) }
  }
  return <Modal title={group ? 'Edycja grupy' : 'Nowa grupa celów'} onClose={onClose} footer={<><button onClick={onClose}>Anuluj</button><button className="primary" onClick={save}>Zapisz</button></>}>
    <div className="stack">
      <label className="f"><span>Nazwa</span><input value={f.name} onChange={e => set('name', e.target.value)} placeholder="np. Instytut_A" /></label>
      <label className="f"><span>Opis</span><input value={f.description} onChange={e => set('description', e.target.value)} /></label>
      <div className="form-grid">
        <label className="f"><span>Budżet pakietów/s (cała grupa)</span><input type="number" value={f.rate_pps} onChange={e => set('rate_pps', e.target.value)} /></label>
        <label className="f"><span>Żądania HTTP/s</span><input type="number" value={f.http_rps} onChange={e => set('http_rps', e.target.value)} /></label>
        <label className="f"><span>Równoległe zadania sweep</span><input type="number" value={f.max_parallel_sweeps} onChange={e => set('max_parallel_sweeps', e.target.value)} /></label>
        <label className="f"><span>Równoległe zadania probe</span><input type="number" value={f.max_parallel_probes} onChange={e => set('max_parallel_probes', e.target.value)} /></label>
        <label className="f"><span>Profil</span><select value={f.profile_id} onChange={e => set('profile_id', e.target.value)}><option value="">domyślny</option>{profiles?.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}</select></label>
        <label className="f"><span>Strefa czasowa</span><input value={f.timezone} onChange={e => set('timezone', e.target.value)} /></label>
      </div>
      <label className="check"><input type="checkbox" checked={f.always_allowed} onChange={e => set('always_allowed', e.target.checked)} />Bez zdefiniowanych okien skanowanie dozwolone zawsze</label>
      <div className="hint">Budżet jest wspólny dla wszystkich workerów pracujących nad grupą – dokładanie workerów nie zwiększa ruchu ponad limit.</div>
      <ErrorNote e={err} />
    </div>
  </Modal>
}

function Workers() {
  const { data, reload } = useApi<any[]>('/workers')
  useEvents(['task'], reload, 2000)
  if (!data) return null
  if (!data.length) return <Panel><Empty title="Brak workerów">Wygeneruj token w Administracja → Workery i uruchom <code>asi worker</code>.</Empty></Panel>
  return <Panel pad={false}><table className="tbl">
    <thead><tr><th>Worker</th><th>Stan</th><th>Tempo</th><th>Uprawnienia</th><th>Narzędzia</th><th>Uwagi</th></tr></thead>
    <tbody>{data.map(w => <tr key={w.id}>
      <td><b>{w.name}</b><div className="sub">{w.vantage}</div></td>
      <td><span className={'dot ' + (w.online ? 'green' : '')} />{w.online ? (w.current_task ? 'pracuje' : 'bezczynny') : 'offline'}<div className="sub">{ago(w.last_heartbeat)}</div></td>
      <td className="small">{w.current_rate ? num(w.current_rate) + ' pps' : '—'}</td>
      <td className="small">{w.capabilities?.syn ? <span className="badge green">SYN / raw</span> : <span className="badge amber">TCP connect</span>}</td>
      <td className="small mono">{Object.entries(w.tools || {}).map(([k, v]: any) => <div key={k}>{k}: {String(v).slice(0, 40)}</div>)}</td>
      <td className="small">{w.warnings?.map((x: string, i: number) => <div key={i} className="muted">{x}</div>)}</td>
    </tr>)}</tbody>
  </table></Panel>
}

