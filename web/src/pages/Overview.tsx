import { Link, useNavigate } from 'react-router-dom'
import { api, useApi, useEvents } from '../api'
import { Bars, Cat, ChangeType, Empty, HostLink, Panel, Score, State, Top, ago, dur, keyLabel, num, pct, useAuth, useToast } from '../ui'

export default function Overview() {
  const { data, reload } = useApi<any>('/dashboard')
  const { can } = useAuth()
  const toast = useToast()
  const nav = useNavigate()
  useEvents(['run', 'task', 'changes', 'import'], reload, 1500)
  if (!data) return <><Top title="Przegląd" /><div className="page muted">Wczytywanie…</div></>
  const k = data.kpi, d = data.delta || {}
  const baseline = d._baseline === 1
  const newCount = (d.HOST_NEW || 0) + (d.SERVICE_NEW || 0)
  const changed = (d.SERVICE_CHANGED || 0) + (d.HTTP_CHANGED || 0) + (d.TLS_CHANGED || 0)
  const ack = async (id: number) => {
    await api('/changes/ack', { body: { ids: [id] } })
    reload(); toast('Oznaczono jako przejrzane')
  }
  const trend = (data.trend || []).slice(-14).map((t: any) => ({
    label: new Date(t.finished_at).toLocaleDateString('pl-PL', { day: '2-digit', month: '2-digit' }),
    values: [
      { v: t.stats?.new || 0, color: 'var(--blue)', name: 'nowe' },
      { v: t.stats?.changed || 0, color: 'var(--amber)', name: 'zmienione' },
      { v: t.stats?.gone || 0, color: 'var(--faint)', name: 'zniknęło' },
    ],
  }))
  return <>
    <Top title="Przegląd">
      {can('scans:start') && <button className="primary" onClick={() => nav('/scans')}>Nowy skan</button>}
    </Top>
    <div className="page stack">
      <div className="kpis">
        <Kpi v={k.hosts} l="aktywne hosty" to="/assets/hosts" />
        <Kpi v={k.services} l="usługi" to="/assets/services" />
        <Kpi v={k.web} l="strony WWW" to="/assets/web" />
        <Kpi v={baseline ? '—' : newCount} l={baseline ? 'nowe (pierwszy skan)' : 'nowe od ostatniego skanu'} to="/changes?type=HOST_NEW,SERVICE_NEW" />
        <Kpi v={baseline ? '—' : changed} l="zmienione" to="/changes?type=SERVICE_CHANGED,HTTP_CHANGED,TLS_CHANGED" />
        <Kpi v={k.gone_7d} l="zniknęło (7 dni)" to="/changes?type=HOST_GONE,SERVICE_GONE" />
        <Kpi v={k.flapping} l="niestabilne hosty" to="/assets/hosts?q=label:flapping" />
        <Kpi v={k.findings_open} l="otwarte znaleziska" to="/findings" />
      </div>

      {data.runs?.length > 0 && <Panel title="Skany" pad={false} actions={<Link to="/scans" className="small">wszystkie</Link>}>
        <table className="tbl compact"><tbody>
          {data.runs.map((r: any) => <tr key={r.id} className="click" onClick={() => nav('/scans/runs/' + r.id)}>
            <td style={{ width: 200 }}><b>{r.group_name || 'import'}</b><div className="sub">{r.mode} · {ago(r.created_at)}</div></td>
            <td style={{ width: 130 }}><State s={r.status} />{r.phase?.startsWith('retry') && <div className="sub">powtórny pomiar</div>}</td>
            <td><div className="progress"><i style={{ width: pct(r.status === 'COMPLETED' ? 1 : r.eta?.progress ?? (r.total_addresses ? r.done_addresses / r.total_addresses : 0)) }} /></div>
              <div className="sub" style={{ marginTop: 3 }}>{num(r.done_addresses)} / {num(r.total_addresses)} adresów{r.rate_pps ? ` · ${num(r.rate_pps)} pps` : ''}{r.paused_reason ? ` · ${r.paused_reason}` : ''}</div></td>
            <td className="right nowrap" style={{ width: 160 }}>{r.status === 'COMPLETED' ? <span className="sub">zakończony {ago(r.finished_at)}</span> : r.eta ? <span className="sub">pozostało ok. {dur(r.eta.remaining_sec)}{r.eta.finish_at ? <><br />koniec {r.eta.finish_at}</> : null}</span> : null}</td>
          </tr>)}
        </tbody></table>
      </Panel>}

      <div className="grid g-main">
        <Panel title="Do przejrzenia" pad={false} actions={<span className="hint">posortowane wg priorytetu analitycznego</span>}>
          {!data.queue?.length && <Empty title="Nic pilnego">Nowe zmiany i istotne znaleziska pojawią się tutaj po kolejnych skanach.</Empty>}
          {data.queue?.map((q: any, i: number) => <div className="queue-item" key={i}>
            <Score v={q.priority} />
            <div style={{ minWidth: 0 }}>
              <div className="row tight">{q.kind === 'change' ? <ChangeType t={q.type} /> : <span className="badge red">ryzyko</span>}
                <HostLink ip={q.ip}>{keyLabel(q.key)}</HostLink></div>
              <div className="t ellipsis" style={{ marginTop: 3 }} title={q.title}>{q.title}</div>
              <div className="why">{q.kind === 'entity' ? q.reason : `${q.reason} · ${ago(q.at)}`}</div>
            </div>
            <div className="row tight">
              {q.kind === 'change' && can('results:update') && <button className="sm ghost" onClick={() => ack(q.change_id)} title="Oznacz jako przejrzane">✓</button>}
              <button className="sm" onClick={() => nav('/hosts/' + q.ip)}>Otwórz</button>
            </div>
          </div>)}
        </Panel>
        <div className="stack">
          <Panel title="Zmiany w ostatnich skanach">
            <Bars series={trend} />
            <div className="legend" style={{ marginTop: 8 }}><span><i style={{ background: 'var(--blue)' }} />nowe</span><span><i style={{ background: 'var(--amber)' }} />zmienione</span><span><i style={{ background: 'var(--faint)' }} />zniknęło</span></div>
          </Panel>
          <Panel title="Otwarte znaleziska">
            {Object.keys(data.findings_by_category || {}).length === 0 ? <span className="muted">brak</span> :
              <div className="row">{Object.entries(data.findings_by_category).sort((a: any, b: any) => b[1] - a[1]).map(([c, n]: any) =>
                <Link key={c} to={`/findings?q=${c}`}><Cat c={c} /> <b>{n}</b></Link>)}</div>}
            {k.certs_expiring > 0 && <div className="hint" style={{ marginTop: 8 }}>{k.certs_expiring} certyfikatów wygasa w ciągu 30 dni lub już wygasło</div>}
          </Panel>
          <Panel title="Grupy podobnych usług" actions={<Link to="/clusters" className="small">wszystkie</Link>} pad={false}>
            {!data.clusters?.length ? <Empty title="Brak grup" /> : <table className="tbl compact"><tbody>{data.clusters.map((c: any) =>
              <tr key={c.key} className="click" onClick={() => nav('/clusters?key=' + c.key)}><td className="num" style={{ width: 40 }}><b>{c.count}</b></td>
                <td><div className="ellipsis" style={{ maxWidth: 230 }}>{c.title || c.server || 'bez tytułu'}</div><div className="sub">{(c.techs || []).slice(0, 3).join(', ')}</div></td><td><Score v={c.max_score} /></td></tr>)}</tbody></table>}
          </Panel>
          <Panel title="Workery i integracje">
            <div className="stack small">
              {(data.workers || []).length === 0 && <span className="muted">Brak zarejestrowanych workerów.</span>}
              {(data.workers || []).map((w: any) => <div key={w.id}><span className={'dot ' + (w.online ? 'green' : '')} /><b>{w.name}</b> <span className="muted">{w.online ? (w.current_rate ? `${w.current_rate} pps` : 'bezczynny') : 'offline ' + ago(w.last_heartbeat)}</span>
                {w.warnings?.length > 0 && <div className="faint" style={{ marginLeft: 13 }}>{w.warnings[0]}</div>}</div>)}
              <div><span className={'dot ' + (data.defectdojo?.configured ? (data.defectdojo.last_error ? 'red' : 'green') : '')} /><b>DefectDojo</b> <span className="muted">
                {data.defectdojo?.configured ? (data.defectdojo.last_error ? 'błąd synchronizacji' : data.defectdojo.last_sync ? 'synchronizacja ' + ago(data.defectdojo.last_sync) : 'skonfigurowane') : 'nieskonfigurowane'}</span></div>
            </div>
          </Panel>
        </div>
      </div>
    </div>
  </>
}

function Kpi({ v, l, to }: { v: any; l: string; to: string }) {
  return <div className="kpi"><Link to={to}><div className="v">{typeof v === 'number' ? num(v) : v}</div><div className="l">{l}</div></Link></div>
}


