import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api, qs, useApi } from '../api'
import { Cat, Empty, FStatus, HostLink, Modal, Pager, Panel, SearchBox, Sev, Top, ago, dt, keyLabel, useAuth, useToast } from '../ui'

export default function Findings() {
  const [sp, setSp] = useSearchParams()
  const q = sp.get('q') || ''
  const [status, setStatus] = useState('')
  const [active, setActive] = useState('true')
  const [offset, setOffset] = useState(0)
  const { data, reload } = useApi<any>('/findings' + qs({ q, status, active, limit: 100, offset }))
  const dd = useApi<any>('/defectdojo')
  const { can } = useAuth()
  const toast = useToast()
  const [busy, setBusy] = useState(false)
  const [show, setShow] = useState<any>(null)
  const sync = async () => {
    setBusy(true)
    try { const r = await api('/defectdojo/sync', { method: 'POST' }); toast('Zsynchronizowano: ' + JSON.stringify(r.statuses || {})); reload(); dd.reload() } catch (e: any) { toast(e.message, true) } finally { setBusy(false) }
  }
  const triage = async (f: any, st: string) => { try { await api(`/findings/${f.id}/triage`, { body: { status: st } }); toast('Zapisano decyzję'); reload() } catch (e: any) { toast(e.message, true) } }
  const push = async (f: any) => { try { await api('/findings/push', { body: { ids: [f.id] } }); toast('Wysłano'); reload() } catch (e: any) { toast(e.message, true) } }
  const cfg = dd.data?.config
  return <>
    <Top title="Znaleziska">
      <SearchBox value={q} onChange={v => { setOffset(0); setSp(v ? { q: v } : {}) }} placeholder="tytuł, adres, kategoria…" />
      {can('defectdojo:triage') && <button onClick={sync} disabled={busy || !cfg?.url}>{busy ? 'Synchronizuję…' : 'Synchronizuj z DefectDojo'}</button>}
    </Top>
    <div className="page stack">
      <div className="notice">
        Znaleziska informacyjne powstają z sygnatur oznaczonych do eksportu. Trafiają do DefectDojo jako <b>Generic Findings Import</b> (reimport do tego samego testu).
        DefectDojo deduplikuje je, a decyzje analityka (false positive, risk accepted) wracają tutaj i obniżają ocenę encji. {cfg?.url ? <>Instancja: <span className="mono">{cfg.url}</span>{cfg.last_sync && ` · ostatnia synchronizacja ${ago(cfg.last_sync)}`}</> : 'Integracja nie jest skonfigurowana (Administracja → DefectDojo).'}
        {cfg?.last_error && <div className="conflict">Ostatni błąd: {cfg.last_error}</div>}
      </div>
      <div className="row">
        {[['', 'wszystkie'], ['open', 'otwarte'], ['false_positive', 'false positive'], ['risk_accepted', 'zaakceptowane'], ['mitigated', 'naprawione']].map(([k, l]) =>
          <button key={k} className={'sm' + (status === k ? ' primary' : '')} onClick={() => { setStatus(k); setOffset(0) }}>{l}</button>)}
        <label className="check"><input type="checkbox" checked={active === ''} onChange={e => setActive(e.target.checked ? '' : 'true')} />pokaż nieaktualne</label>
      </div>
      <Panel pad={false}>
        {!data?.items?.length ? <Empty title="Brak znalezisk">Pojawią się po skanie, gdy sygnatury z eksportem do DefectDojo coś wykryją.</Empty> : <>
          <table className="tbl">
            <thead><tr><th>Ważność</th><th>Znalezisko</th><th>Kategoria</th><th>Status</th><th>DefectDojo</th><th>Ostatnio</th><th /></tr></thead>
            <tbody>{data.items.map((f: any) => <tr key={f.id} className={f.active ? '' : 'dim'}>
              <td><Sev s={f.severity} /></td>
              <td><a style={{ cursor: 'pointer' }} onClick={() => setShow(f)}>{f.title.replace('[ASI] ', '')}</a><div className="sub"><HostLink ip={f.host_ip}>{keyLabel(f.entity_key)}</HostLink> · {f.rule}</div></td>
              <td>{f.category && <Cat c={f.category} />}</td>
              <td><FStatus s={f.status} /></td>
              <td className="small">{f.dd_finding_id ? <span className="mono">#{f.dd_finding_id}</span> : f.exported ? <span className="muted">oczekuje</span> : <span className="faint">nie eksportowane</span>}</td>
              <td className="small muted nowrap">{ago(f.last_seen)}</td>
              <td className="right nowrap">
                {can('defectdojo:push') && !f.dd_finding_id && <button className="sm ghost" onClick={() => push(f)}>wyślij</button>}
                {can('defectdojo:triage') && f.status === 'open' && <button className="sm ghost" onClick={() => triage(f, 'false_positive')}>false positive</button>}
                {can('defectdojo:triage') && f.status !== 'open' && <button className="sm ghost" onClick={() => triage(f, 'open')}>przywróć</button>}
              </td>
            </tr>)}</tbody>
          </table>
          <Pager total={data.total} limit={100} offset={offset} onPage={setOffset} /></>}
      </Panel>
      {dd.data?.log?.length > 0 && <Panel title="Dziennik synchronizacji" pad={false}><table className="tbl compact"><tbody>{dd.data.log.slice(0, 10).map((l: any, i: number) =>
        <tr key={i}><td className="small muted nowrap">{dt(l.at)}</td><td className="small">{l.direction}</td><td>{l.status === 'ok' ? <span className="badge green">ok</span> : <span className="badge red">błąd</span>}</td><td className="small">{l.details}</td></tr>)}</tbody></table></Panel>}
    </div>
    {show && <Modal title={show.title} onClose={() => setShow(null)} wide>
      <dl className="kv"><dt>Reguła</dt><dd className="mono">{show.rule}</dd><dt>Encja</dt><dd className="mono">{show.entity_key}</dd><dt>Komponent</dt><dd>{show.component_name} {show.component_version}</dd>
        <dt>Pierwszy raz</dt><dd>{dt(show.first_seen)}</dd><dt>Wysłano</dt><dd>{dt(show.last_pushed_at)}</dd></dl>
      <h3 style={{ marginTop: 12 }}>Opis (deterministyczny – wchodzi do hash_code DefectDojo)</h3>
      <pre className="pre">{show.description}</pre>
    </Modal>}
  </>
}
