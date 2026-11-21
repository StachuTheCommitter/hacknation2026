import { useEffect, useState } from 'react'
import { api, download, useApi } from '../api'
import { Cat, Empty, ErrorNote, Modal, Panel, SearchBox, Top, useAuth, useToast } from '../ui'

const TEMPLATE = `id: moja-sygnatura
name: Panel administracyjny XYZ
description: Wykrywa panel logowania aplikacji XYZ.
scope: http                # http | service | host
categories: [admin_panel]
severity: info             # info | low | medium | high
priority: 25               # wkład do oceny „ciekawości” (0–100)
confidence: 0.85           # waga dowodu (0–1)
# request:                 # odkomentuj, by sprawdzać ścieżkę (tylko GET/HEAD)
#   method: GET
#   path: /xyz/login
match:
  all:
    - {part: status, op: in, value: [200, 401]}
    - any:
        - {part: title, op: icontains, value: "xyz admin"}
        - {part: cookie_name, op: equals, value: XYZSESSID}
        - {part: header, name: Server, op: regex, value: "XYZ/[0-9.]+"}
export:
  defectdojo: true
  title: "XYZ admin panel exposed"
`

export default function Signatures() {
  const { data, reload } = useApi<any[]>('/signatures')
  const { can } = useAuth()
  const toast = useToast()
  const [q, setQ] = useState('')
  const [edit, setEdit] = useState<any>(null)
  const [origin, setOrigin] = useState('')
  const list = (data || []).filter(s => (!q || (s.sig_id + s.name + s.categories?.join(' ')).toLowerCase().includes(q.toLowerCase())) && (!origin || s.origin.startsWith(origin)))
  const toggle = async (s: any) => { await api(`/signatures/${s.sig_id}/toggle`, { body: { enabled: !s.enabled } }); reload() }
  const importFile = async (f: File) => {
    const fd = new FormData(); fd.append('file', f)
    try { const r = await api('/signatures/import', { form: fd }); toast(`Zaimportowano: ${r.created} nowych, ${r.updated} zaktualizowanych${r.errors?.length ? `, błędy: ${r.errors.length}` : ''}`, r.errors?.length > 0); reload() } catch (e: any) { toast(e.message, true) }
  }
  return <>
    <Top title="Sygnatury">
      <SearchBox value={q} onChange={setQ} placeholder="id, nazwa, kategoria…" />
      <button onClick={() => download('/signatures-export')}>Eksport YAML</button>
      {can('signatures:create') && <label className="btn">Import (ASI / nuclei)<input type="file" hidden accept=".yaml,.yml,.json" onChange={e => e.target.files?.[0] && importFile(e.target.files[0])} /></label>}
      {can('signatures:create') && <button className="primary" onClick={() => setEdit({ source: TEMPLATE, isNew: true })}>Nowa sygnatura</button>}
    </Top>
    <div className="page stack">
      <div className="row">
        {[['', 'wszystkie'], ['builtin', 'wbudowane'], ['user', 'użytkownika'], ['imported', 'zaimportowane']].map(([k, l]) => <button key={k} className={'sm' + (origin === k ? ' primary' : '')} onClick={() => setOrigin(k)}>{l}</button>)}
        <span className="hint">Sygnatury pasywne działają na zapisanych danych (także importowanych). Aktywne dodatkowo pobierają wskazaną ścieżkę metodą GET – bez logowania i payloadów.</span>
      </div>
      <Panel pad={false}>
        {!list.length ? <Empty title="Brak sygnatur" /> : <table className="tbl">
          <thead><tr><th>Sygnatura</th><th>Rodzaj</th><th>Kategorie</th><th>Ważność</th><th className="num">Priorytet</th><th className="num">Trafienia</th><th>Źródło</th><th /></tr></thead>
          <tbody>{list.map(s => <tr key={s.id} className={s.enabled ? '' : 'dim'}>
            <td><b>{s.name}</b><div className="sub mono">{s.sig_id} · v{s.version}</div></td>
            <td className="small">{s.kind === 'active' ? <span className="badge blue">aktywna</span> : <span className="badge">pasywna</span>} <span className="muted">{s.scope}</span></td>
            <td><div className="row tight">{s.categories?.map((c: string) => <Cat key={c} c={c} />)}</div></td>
            <td className="small">{s.severity}</td><td className="num">{s.priority}</td><td className="num">{s.matches}</td>
            <td className="small muted">{s.origin}</td>
            <td className="right nowrap">
              {can('signatures:update') && <button className="ghost sm" onClick={() => toggle(s)}>{s.enabled ? 'wyłącz' : 'włącz'}</button>}
              <button className="ghost sm" onClick={() => setEdit(s)}>{can('signatures:update') ? 'edytuj' : 'podgląd'}</button>
            </td>
          </tr>)}</tbody>
        </table>}
      </Panel>
    </div>
    {edit && <Editor sig={edit} onClose={() => { setEdit(null); reload() }} />}
  </>
}

function Editor({ sig, onClose }: { sig: any; onClose: () => void }) {
  const { can } = useAuth()
  const toast = useToast()
  const [src, setSrc] = useState(sig.source)
  const [val, setVal] = useState<any>(null)
  const [err, setErr] = useState<any>(null)
  const [testKey, setTestKey] = useState('')
  const [test, setTest] = useState<any>(null)
  const [hunt, setHunt] = useState<any>(null)
  const [busy, setBusy] = useState(false)
  const editable = sig.isNew ? can('signatures:create') : can('signatures:update')
  useEffect(() => { const t = setTimeout(() => api('/signatures/validate', { body: { source: src } }).then(setVal).catch(() => {}), 300); return () => clearTimeout(t) }, [src])
  const save = async () => {
    try { sig.isNew ? await api('/signatures', { body: { source: src } }) : await api('/signatures/' + sig.sig_id, { method: 'PUT', body: { source: src } }); toast('Zapisano sygnaturę'); onClose() } catch (e) { setErr(e) }
  }
  const runTest = async () => { try { setTest(await api('/signatures/test', { body: { source: src, entity_key: testKey } })) } catch (e: any) { toast(e.message, true) } }
  const retro = async () => { setBusy(true); try { setHunt(await api(`/signatures/${sig.sig_id}/retrohunt`, { method: 'POST' })) } catch (e: any) { toast(e.message, true) } finally { setBusy(false) } }
  const del = async () => { if (!confirm('Usunąć sygnaturę?')) return; await api('/signatures/' + sig.sig_id, { method: 'DELETE' }); onClose() }
  return <Modal title={sig.isNew ? 'Nowa sygnatura' : sig.name} onClose={onClose} wide footer={<>
    {!sig.isNew && can('signatures:delete') && <button className="danger" onClick={del}>Usuń</button>}
    {!sig.isNew && can('signatures:update') && <button onClick={retro} disabled={busy} title="Dopasuj do zapisanych danych bez ponownego skanu">{busy ? 'Szukam…' : 'Uruchom na historii'}</button>}
    <div className="spacer" /><button onClick={onClose}>Zamknij</button>{editable && <button className="primary" onClick={save} disabled={!val?.valid}>Zapisz</button>}</>}>
    <div className="grid g2" style={{ gridTemplateColumns: 'minmax(0,1.3fr) minmax(0,1fr)' }}>
      <div>
        <textarea className="code" rows={24} value={src} onChange={e => setSrc(e.target.value)} readOnly={!editable} spellCheck={false} />
        <div style={{ marginTop: 6 }}>{val && (val.valid ? <div className="notice ok">Poprawna · {val.kind === 'active' ? 'aktywna' : 'pasywna'} · scope {val.scope}</div> :
          <div className="notice err">{val.errors?.map((e: string, i: number) => <div key={i}>{e}</div>)}</div>)}</div>
        <ErrorNote e={err} />
      </div>
      <div className="stack">
        <div><h3>Test na encji</h3>
          <div className="row"><input className="mono" style={{ flex: 1 }} value={testKey} onChange={e => setTestKey(e.target.value)} placeholder="np. 10.77.2.20/tcp/80/http/-" /><button className="sm" onClick={runTest} disabled={!testKey}>Testuj</button></div>
          <div className="hint" style={{ marginTop: 4 }}>Klucz endpointu WWW (ip/tcp/port/schemat/vhost) albo usługi (ip/tcp/port) – widoczny na stronie hosta.</div>
          {test && (test.valid === false ? <div className="notice err">{test.errors?.join('; ')}</div> : test.results?.map((r: any) => <div key={r.subject} style={{ marginTop: 8 }}>
            <div className="row"><b className="mono small">{r.subject}</b>{r.matched ? <span className="badge green">pasuje</span> : <span className="badge">nie pasuje</span>}{r.version && <span className="badge blue">wersja {r.version}</span>}</div>
            <table className="tbl compact" style={{ marginTop: 4 }}><tbody>{(r.trace || []).map((t: any, i: number) => <tr key={i}><td>{t.ok ? '✓' : '✗'}</td><td className="mono small">{t.rule}</td><td className="small muted ellipsis" style={{ maxWidth: 160 }}>{(t.values || []).join(' | ')}</td></tr>)}</tbody></table>
          </div>))}
        </div>
        {hunt && <div className="notice ok">Sprawdzono {hunt.checked} encji, trafień: {hunt.matched}{hunt.skipped ? ` (pominięto ${hunt.skipped} – ścieżka nie była jeszcze pobrana)` : ''}
          {hunt.hits?.length > 0 && <div className="mono small" style={{ marginTop: 4 }}>{hunt.hits.slice(0, 10).join('\n')}</div>}</div>}
        <div><h3>Ściąga</h3><div className="small muted">
          <b>Części (http):</b> status, title, header (+name), header_names, cookie_name, cookie (+name, attr), body, favicon_mmh3, tech, tech_version (+name), tls_expired, tls_days_left, tls_self_signed, tls_subject_cn, vhost, scheme, port, soft404, path, pattern_match<br />
          <b>Części (service):</b> port, proto, service, product, version, banner, cpe, devicetype<br />
          <b>Operatory:</b> equals, iequals, contains, icontains, starts_with, regex (RE2), in, exists, not_exists, lt, gt, between, version_lt, version_gte<br />
          <b>Grupy:</b> all, any, not – zagnieżdżalne</div></div>
      </div>
    </div>
  </Modal>
}
