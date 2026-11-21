import { Link, useNavigate, useParams } from 'react-router-dom'
import { api, useApi, useEvents } from '../api'
import { ChangeType, Empty, HostLink, Panel, State, Top, ago, dt, dur, keyLabel, num, pct, useAuth, useToast } from '../ui'

export default function Run() {
  const { id = '' } = useParams()
  const { data: r, reload } = useApi<any>('/runs/' + id)
  const tasks = useApi<any[]>('/runs/' + id + '/tasks')
  const changes = useApi<any[]>('/changes?run_id=' + id + '&limit=300')
  useEvents(['run', 'task', 'changes'], () => { reload(); tasks.reload(); changes.reload() }, 1000)
  const { can } = useAuth()
  const toast = useToast()
  const nav = useNavigate()
  if (!r) return <><Top title="Przebieg" /><div className="page muted">Wczytywanie…</div></>
  const ctl = async (a: string) => { try { await api(`/runs/${id}/${a}`, { method: 'POST' }); reload(); toast('OK') } catch (e: any) { toast(e.message, true) } }
  const p = r.status === 'COMPLETED' ? 1 : r.total_addresses ? r.done_addresses / r.total_addresses : 0
  const active = ['RUNNING', 'PAUSED_WINDOW', 'PAUSED_MANUAL', 'PENDING'].includes(r.status)
  const ts = tasks.data || []
  const byKind = (k: string) => ts.filter(t => t.kind === k)
  const sweepDone = byKind('sweep').filter(t => t.status === 'done')
  const avgSweep = sweepDone.length ? sweepDone.reduce((a, t) => a + t.duration_ms, 0) / sweepDone.length / 1000 : 0
  return <>
    <Top title={<>{r.group_name || 'Import'} <span className="muted" style={{ fontWeight: 400 }}>· {r.mode}</span></>} crumbs={<><Link to="/scans">Skany</Link> · {dt(r.created_at)}</>}>
      {active && can('scans:control') && (r.status === 'PAUSED_MANUAL' ? <button onClick={() => ctl('resume')}>Wznów</button> : <button onClick={() => ctl('pause')}>Wstrzymaj</button>)}
      {active && can('scans:control') && <button className="danger" onClick={() => confirm('Anulować przebieg?') && ctl('cancel')}>Anuluj</button>}
      {r.status === 'COMPLETED' && <button onClick={() => nav('/changes?tab=diff&b=' + id)}>Porównaj z innym</button>}
    </Top>
    <div className="page stack">
      <div className="kpis">
        <div className="kpi"><div className="v"><State s={r.status} /></div><div className="l">{r.paused_reason || (r.phase !== 'done' && r.phase !== 'scan' ? 'faza: ' + r.phase : 'stan')}</div></div>
        <div className="kpi"><div className="v">{pct(p)}</div><div className="l">{num(r.done_addresses)} / {num(r.total_addresses)} adresów</div></div>
        <div className="kpi"><div className="v">{r.rate_pps ? num(r.rate_pps) : '—'}</div><div className="l">bieżące tempo (pps)</div></div>
        <div className="kpi"><div className="v">{r.finished_at ? dur((new Date(r.finished_at).getTime() - new Date(r.started_at).getTime()) / 1000) : r.eta ? '~' + dur(r.eta.remaining_sec) : '—'}</div>
          <div className="l">{r.finished_at ? 'czas trwania' : 'pozostało' + (r.eta?.finish_at ? ` (koniec ${r.eta.finish_at})` : '')}</div></div>
        <div className="kpi"><div className="v">{r.stats?.hosts_up ?? '—'}</div><div className="l">hosty odpowiadające</div></div>
        <div className="kpi"><div className="v">{r.stats?.new ?? '—'} / {r.stats?.changed ?? '—'} / {r.stats?.gone ?? '—'}</div><div className="l">nowe / zmienione / zniknęły</div></div>
      </div>
      {r.status !== 'COMPLETED' && <div className="progress"><i style={{ width: pct(p) }} /></div>}
      {r.note && <div className="notice">{r.note}</div>}
      <div className="grid g2">
        <Panel title="Zadania" actions={<span className="hint">{ts.length} zadań · średnio {avgSweep ? dur(avgSweep) : '—'} na zadanie sweep</span>}>
          {['sweep', 'probe', 'retry', 'dns'].map(k => byKind(k).length > 0 && <div key={k} style={{ marginBottom: 10 }}>
            <div className="small muted" style={{ marginBottom: 4 }}>{{ sweep: 'discovery + porty', probe: 'usługi + WWW', retry: 'powtórne pomiary', dns: 'DNS' }[k]} ({byKind(k).filter(t => t.status === 'done').length}/{byKind(k).length})</div>
            <div className="taskgrid">{byKind(k).map(t => <i key={t.id} className={t.status} title={`${t.label} · ${t.status}${t.worker ? ' · ' + t.worker : ''}${t.duration_ms ? ' · ' + dur(t.duration_ms / 1000) : ''}${t.error ? ' · ' + t.error : ''}`} />)}</div>
          </div>)}
          {!ts.length && <span className="muted">Brak zadań{r.source !== 'scanner' ? ' – przebieg z importu' : ' – czekam na worker'}.</span>}
          {ts.some(t => t.status === 'failed') && <div className="notice err" style={{ marginTop: 8 }}>{ts.filter(t => t.status === 'failed').slice(0, 3).map(t => <div key={t.id}>{t.label}: {t.error}</div>)}</div>}
        </Panel>
        <Panel title="Profil">
          <dl className="kv small">
            <dt>Porty TCP</dt><dd className="mono">{r.profile.tcp_ports}</dd>
            {r.profile.udp_ports && <><dt>Porty UDP</dt><dd className="mono">{r.profile.udp_ports}</dd></>}
            <dt>Discovery</dt><dd>{r.profile.discovery_engine} {r.profile.discovery_icmp && '· ICMP'} · SYN {r.profile.discovery_tcp_syn}</dd>
            <dt>Skan portów</dt><dd>{r.profile.portscan_engine} · {r.profile.portscan_scope === 'all' ? 'wszystkie adresy' : 'tylko żywe hosty'}</dd>
            <dt>nmap -sV</dt><dd>intensywność {r.profile.nmap_intensity} · skrypty {r.profile.nmap_scripts?.join(', ')}</dd>
            <dt>HTTP</dt><dd>{r.profile.http_enabled ? `${r.profile.prober_paths?.length} ścieżek, sygnatury aktywne: ${r.profile.active_signatures ? 'tak' : 'nie'}` : 'wyłączone'}</dd>
            <dt>Powtórki</dt><dd>{r.profile.retry_delays_sec?.map((s: number) => dur(s)).join(', ')}</dd>
            <dt>Utworzył</dt><dd>{r.created_by}</dd>
          </dl>
        </Panel>
      </div>
      <Panel title={`Zmiany w tym przebiegu (${changes.data?.length || 0})`} pad={false}>
        {!changes.data?.length ? <Empty title="Brak zmian" /> : <table className="tbl compact"><tbody>{changes.data.slice(0, 200).map(c =>
          <tr key={c.id}><td style={{ width: 140 }}><ChangeType t={c.type} /></td><td className="nowrap">{c.host_ip ? <HostLink ip={c.host_ip}>{keyLabel(c.entity_key)}</HostLink> : c.entity_key}</td><td className="small">{c.summary}</td><td className="small muted nowrap">{ago(c.at)}</td></tr>)}</tbody></table>}
      </Panel>
    </div>
  </>
}
