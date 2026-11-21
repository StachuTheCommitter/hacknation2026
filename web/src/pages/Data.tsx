import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api, download, qs, useApi } from '../api'
import { Empty, ErrorNote, Panel, Tabs, Top, ago, num, pct, useAuth, useToast } from '../ui'

export default function Data() {
  const [sp, setSp] = useSearchParams()
  const { can } = useAuth()
  const tab = sp.get('tab') || (can('results:create') ? 'import' : 'export')
  const items: [string, string][] = []
  if (can('results:create')) items.push(['import', 'Import wyników'], ['form', 'Dodaj ręcznie'])
  if (can('export:use')) items.push(['export', 'Eksport'])
  items.push(['eval', 'Ocena trafności'], ['history', 'Historia importów'])
  return <>
    <Top title="Import i eksport" />
    <div className="page">
      <Tabs items={items} value={tab} onChange={t => setSp({ tab: t })} />
      {tab === 'import' && <Import />}
      {tab === 'form' && <ManualForm />}
      {tab === 'export' && <Export />}
      {tab === 'eval' && <Eval />}
      {tab === 'history' && <History />}
    </div>
  </>
}

function Import() {
  const { data: groups } = useApi<any[]>('/target-groups')
  const [file, setFile] = useState<File | null>(null)
  const [group, setGroup] = useState('')
  const [dry, setDry] = useState<any>(null)
  const [res, setRes] = useState<any>(null)
  const [err, setErr] = useState<any>(null)
  const toast = useToast()
  const send = async (dryRun: boolean) => {
    if (!file) return
    setErr(null)
    const fd = new FormData(); fd.append('file', file); fd.append('group_id', group); if (dryRun) fd.append('dry_run', 'true')
    try { const r = await api('/import/observations', { form: fd }); dryRun ? setDry(r) : (setRes(r), setDry(null), toast('Zaimportowano')) } catch (e) { setErr(e) }
  }
  return <div className="grid g2">
    <Panel title="Plik z wynikami">
      <div className="stack">
        <input type="file" accept=".json,.jsonl,.csv,.xml,.txt" onChange={e => { setFile(e.target.files?.[0] || null); setDry(null); setRes(null) }} />
        <label className="f"><span>Przypisz do grupy (opcjonalnie)</span><select value={group} onChange={e => setGroup(e.target.value)}><option value="">— bez grupy —</option>{groups?.map(g => <option key={g.id} value={g.id}>{g.name}</option>)}</select></label>
        <div className="row"><button onClick={() => send(true)} disabled={!file}>Sprawdź (bez zapisu)</button><button className="primary" onClick={() => send(false)} disabled={!file}>Importuj</button></div>
        <ErrorNote e={err} />
        {dry && <div className={'notice ' + (dry.errors.length ? 'warn' : 'ok')}>Format: <b>{dry.format}</b> · {dry.hosts} hostów, {dry.services} usług, {dry.http} stron WWW
          {dry.errors.length > 0 && <ul style={{ margin: '6px 0 0', paddingLeft: 18 }}>{dry.errors.slice(0, 15).map((e: any, i: number) => <li key={i}><span className="mono">{e.path}</span>: {e.message}</li>)}</ul>}</div>}
        {res && <div className="notice ok">Zaimportowano {res.hosts} hostów i {res.services} usług ({res.format}). Wykryto {res.changes} zmian. <Link to={'/scans/runs/' + res.run_id}>Zobacz przebieg</Link></div>}
      </div>
    </Panel>
    <Panel title="Obsługiwane formaty">
      <ul className="small" style={{ margin: 0, paddingLeft: 18, lineHeight: 1.7 }}>
        <li><b>ASI JSON / JSONL</b> – schemat <code>asi.observation/v1</code> (taki sam jak eksport)</li>
        <li><b>ASI CSV</b> – jedna usługa w wierszu, wymagana kolumna <code>ip</code>; listy rozdzielone <code>;</code></li>
        <li><b>nmap XML</b> (<code>-oX</code>), <b>naabu JSONL</b> (<code>-json</code>), <b>httpx JSONL</b> (<code>-json</code>)</li>
      </ul>
      <p className="small muted">Import przechodzi przez ten sam pipeline co skaner: walidację, zapis obserwacji, sygnatury, klasyfikację, wykrywanie zmian i DefectDojo. Porównania obejmują tylko importowane encje – brak w pliku nie oznacza „zniknięcia”.</p>
      <div className="row"><button className="sm" onClick={() => download('/export?format=csv&q=ip:0.0.0.0')}>Pobierz pusty szablon CSV</button></div>
    </Panel>
  </div>
}

function ManualForm() {
  const { data: groups } = useApi<any[]>('/target-groups')
  const [f, setF] = useState<any>({ ip: '', hostname: '', group: '', proto: 'tcp', port: '', service: '', product: '', version: '', http: false, scheme: 'http', status: '200', title: '', headers: '', cookies: '', note: '', tags: '' })
  const [err, setErr] = useState<any>(null)
  const [res, setRes] = useState<any>(null)
  const set = (k: string, v: any) => setF({ ...f, [k]: v })
  const submit = async () => {
    setErr(null)
    const svc: any = f.port ? { proto: f.proto, port: +f.port, service: f.service, product: f.product, version: f.version } : null
    if (svc && f.http) {
      const headers: Record<string, string> = {}
      f.headers.split('\n').forEach((l: string) => { const i = l.indexOf(':'); if (i > 0) headers[l.slice(0, i).trim()] = l.slice(i + 1).trim() })
      svc.http = [{ scheme: f.scheme, status: +f.status, title: f.title, headers, cookies: f.cookies.split(',').map((c: string) => c.trim()).filter(Boolean).map((name: string) => ({ name })) }]
    }
    const body = { group_id: f.group, observed_at: new Date().toISOString(), host: { ip: f.ip, hostnames: f.hostname ? [f.hostname] : [] }, services: svc ? [svc] : [], note: f.note, tags: f.tags.split(',').map((t: string) => t.trim()).filter(Boolean) }
    try { setRes(await api('/observations', { body })) } catch (e) { setErr(e) }
  }
  return <div className="grid g2">
    <Panel title="Nowa obserwacja">
      <div className="stack">
        <div className="form-grid">
          <label className="f"><span>Adres IP *</span><input className="mono" value={f.ip} onChange={e => set('ip', e.target.value)} placeholder="10.77.1.10" /></label>
          <label className="f"><span>Nazwa hosta</span><input value={f.hostname} onChange={e => set('hostname', e.target.value)} /></label>
          <label className="f"><span>Grupa</span><select value={f.group} onChange={e => set('group', e.target.value)}><option value="">—</option>{groups?.map(g => <option key={g.id} value={g.id}>{g.name}</option>)}</select></label>
          <label className="f"><span>Protokół</span><select value={f.proto} onChange={e => set('proto', e.target.value)}><option>tcp</option><option>udp</option></select></label>
          <label className="f"><span>Port</span><input type="number" value={f.port} onChange={e => set('port', e.target.value)} /></label>
          <label className="f"><span>Usługa</span><input value={f.service} onChange={e => set('service', e.target.value)} placeholder="http, ssh…" /></label>
          <label className="f"><span>Produkt</span><input value={f.product} onChange={e => set('product', e.target.value)} placeholder="nginx" /></label>
          <label className="f"><span>Wersja</span><input value={f.version} onChange={e => set('version', e.target.value)} /></label>
        </div>
        <label className="check"><input type="checkbox" checked={f.http} onChange={e => set('http', e.target.checked)} />usługa WWW – dodaj dane HTTP</label>
        {f.http && <div className="form-grid">
          <label className="f"><span>Schemat</span><select value={f.scheme} onChange={e => set('scheme', e.target.value)}><option>http</option><option>https</option></select></label>
          <label className="f"><span>Kod odpowiedzi</span><input type="number" value={f.status} onChange={e => set('status', e.target.value)} /></label>
          <label className="f"><span>Tytuł strony</span><input value={f.title} onChange={e => set('title', e.target.value)} /></label>
          <label className="f"><span>Nazwy cookies (po przecinku)</span><input value={f.cookies} onChange={e => set('cookies', e.target.value)} /></label>
          <label className="f" style={{ gridColumn: '1 / -1' }}><span>Nagłówki (Nazwa: wartość, po jednym w linii)</span><textarea className="code" rows={3} value={f.headers} onChange={e => set('headers', e.target.value)} placeholder={'Server: nginx/1.24.0\nX-Powered-By: PHP/8.2'} /></label>
        </div>}
        <div className="form-grid">
          <label className="f"><span>Tagi (po przecinku)</span><input value={f.tags} onChange={e => set('tags', e.target.value)} /></label>
          <label className="f"><span>Notatka</span><input value={f.note} onChange={e => set('note', e.target.value)} /></label>
        </div>
        <div className="row"><div className="spacer" /><button className="primary" onClick={submit} disabled={!f.ip}>Dodaj</button></div>
        <ErrorNote e={err} />
        {res && <div className="notice ok">Dodano. Dane przeszły ten sam pipeline co skaner (sygnatury, klasyfikacja, zmiany). <Link to={'/hosts/' + f.ip}>Otwórz host</Link></div>}
      </div>
    </Panel>
    <Panel title="Jak to działa">
      <p className="small muted" style={{ margin: 0 }}>Formularz tworzy obserwację w schemacie kanonicznym i wysyła ją tym samym endpointem co import pliku. Nagłówki i cookies są oceniane przez sygnatury (np. <code>X-Powered-By: PHP/5.6</code> → oprogramowanie bez wsparcia). Dane wrażliwe są szyfrowane w bazie. Wartości można później edytować na stronie hosta – edycje przetrwają kolejne skany.</p>
    </Panel>
  </div>
}

function Export() {
  const { can } = useAuth()
  const [q, setQ] = useState('')
  const [fmt, setFmt] = useState('json')
  const [raw, setRaw] = useState(false)
  const runs = useApi<any[]>('/runs?limit=50')
  const [run, setRun] = useState('')
  return <Panel title="Eksport danych">
    <div className="stack" style={{ maxWidth: 640 }}>
      <div className="form-grid">
        <label className="f"><span>Format</span><select value={fmt} onChange={e => setFmt(e.target.value)}><option value="json">JSON (asi.export/v1)</option><option value="jsonl">JSONL</option><option value="csv">CSV</option></select></label>
        <label className="f"><span>Filtr (jak w widoku zasobów)</span><input value={q} onChange={e => setQ(e.target.value)} placeholder="np. cat:admin_panel" /></label>
        <label className="f"><span>Tylko hosty z przebiegu</span><select value={run} onChange={e => setRun(e.target.value)}><option value="">—</option>{runs.data?.map(r => <option key={r.id} value={r.id}>{new Date(r.created_at).toLocaleString('pl-PL')} · {r.group_name || r.source}</option>)}</select></label>
      </div>
      {can('sensitive:read') ? <label className="check"><input type="checkbox" checked={raw} onChange={e => setRaw(e.target.checked)} />dołącz dane wrażliwe (pełne nagłówki, wartości cookies, treść) – zapisywane w audycie</label>
        : <div className="hint">Twoja rola eksportuje dane bez wartości wrażliwych (maskowanie).</div>}
      <div className="row"><button className="primary" onClick={() => download('/export' + qs({ format: fmt, q, run_id: run, include_raw: raw, include_sensitive: raw }))}>Pobierz</button>
        <span className="hint">Eksport zawiera wartości efektywne (z edycjami analityka) i może być zaimportowany z powrotem.</span></div>
    </div>
  </Panel>
}

function Eval() {
  const runs = useApi<any[]>('/runs?limit=200')
  const [ref, setRef] = useState('')
  const [cand, setCand] = useState('')
  const [res, setRes] = useState<any[] | null>(null)
  const [err, setErr] = useState<any>(null)
  const go = async () => { try { setRes(await api('/eval', { body: { reference_run_id: ref, candidate_run_id: cand } })) } catch (e) { setErr(e) } }
  const label = (r: any) => `${new Date(r.created_at).toLocaleString('pl-PL')} · ${r.group_name || r.source} ${r.note ? '· ' + r.note.slice(0, 30) : ''}`
  return <div className="stack">
    <Panel title="Porównanie z wynikami referencyjnymi">
      <p className="small muted" style={{ marginTop: 0 }}>Zaimportuj wyniki referencyjne (np. od organizatorów) jako zwykły import, a potem porównaj je z przebiegiem skanera. Porównanie obejmuje adresy obecne w referencji.</p>
      <div className="row">
        <label className="f" style={{ flex: 1 }}><span>Referencja</span><select value={ref} onChange={e => setRef(e.target.value)}><option value="">—</option>{runs.data?.map(r => <option key={r.id} value={r.id}>{label(r)}</option>)}</select></label>
        <label className="f" style={{ flex: 1 }}><span>Przebieg skanera</span><select value={cand} onChange={e => setCand(e.target.value)}><option value="">—</option>{runs.data?.map(r => <option key={r.id} value={r.id}>{label(r)}</option>)}</select></label>
        <button className="primary" style={{ alignSelf: 'end' }} onClick={go} disabled={!ref || !cand}>Porównaj</button>
      </div>
      <ErrorNote e={err} />
    </Panel>
    {res && <Panel pad={false}><table className="tbl">
      <thead><tr><th>Wymiar</th><th className="num">Precision</th><th className="num">Recall</th><th className="num">F1</th><th className="num">TP</th><th className="num">FP</th><th className="num">FN</th><th>Brakujące / nadmiarowe</th></tr></thead>
      <tbody>{res.map(m => <tr key={m.name}><td><b>{m.name}</b></td><td className="num">{pct(m.precision)}</td><td className="num">{pct(m.recall)}</td><td className="num">{pct(m.f1)}</td><td className="num">{m.tp}</td><td className="num">{m.fp}</td><td className="num">{m.fn}</td>
        <td className="small mono">{m.missing?.slice(0, 4).map((x: string) => <div key={x} className="conflict">− {x}</div>)}{m.extra?.slice(0, 3).map((x: string) => <div key={x} className="muted">+ {x}</div>)}</td></tr>)}</tbody>
    </table></Panel>}
  </div>
}

function History() {
  const { data } = useApi<any[]>('/imports')
  return <Panel pad={false}>{!data?.length ? <Empty title="Brak importów" /> : <table className="tbl"><thead><tr><th>Plik</th><th>Format</th><th className="num">Hosty</th><th className="num">Usługi</th><th>Kto</th><th>Kiedy</th></tr></thead>
    <tbody>{data.map(i => <tr key={i.id}><td>{i.run_id ? <Link to={'/scans/runs/' + i.run_id}>{i.filename || '—'}</Link> : i.filename}</td><td className="small">{i.format}</td><td className="num">{num(i.stats?.hosts)}</td><td className="num">{num(i.stats?.services)}</td><td className="small">{i.created_by}</td><td className="small muted">{ago(i.created_at)}</td></tr>)}</tbody></table>}</Panel>
}
