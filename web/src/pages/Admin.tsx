import { useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { api, qs, useApi } from '../api'
import { Copy, Empty, ErrorNote, Modal, Panel, SearchBox, Tabs, Top, ago, dt, useAuth, useToast } from '../ui'

export default function Admin() {
  const { tab: t } = useParams()
  const nav = useNavigate()
  const { can } = useAuth()
  const items: [string, string][] = []
  if (can('users:manage')) items.push(['users', 'Użytkownicy'])
  if (can('roles:manage')) items.push(['roles', 'Role'])
  if (can('settings:manage')) items.push(['scope', 'Zakres skanowania'], ['defectdojo', 'DefectDojo'], ['workers', 'Workery'], ['security', 'Szyfrowanie'])
  if (can('audit:read')) items.push(['audit', 'Dziennik audytu'])
  const tab = t || items[0]?.[0]
  return <>
    <Top title="Administracja">{can('killswitch:use') && <KillButton />}</Top>
    <div className="page">
      <Tabs items={items} value={tab} onChange={x => nav('/admin/' + x)} />
      {tab === 'users' && <Users />}
      {tab === 'roles' && <Roles />}
      {tab === 'scope' && <Scope />}
      {tab === 'defectdojo' && <DefectDojo />}
      {tab === 'workers' && <Workers />}
      {tab === 'security' && <Security />}
      {tab === 'audit' && <Audit />}
    </div>
  </>
}

function KillButton() {
  const { data, reload } = useApi<any>('/killswitch')
  const toast = useToast()
  const set = async (active: boolean) => {
    const reason = active ? prompt('Powód zatrzymania wszystkich skanów:') : 'wznowienie'
    if (active && reason === null) return
    await api('/killswitch', { body: { active, reason } }); reload(); toast(active ? 'Wszystkie skany zatrzymane' : 'Skanowanie wznowione')
  }
  return data?.active ? <button onClick={() => set(false)}>Wznów skanowanie</button> : <button className="danger solid" onClick={() => set(true)}>Zatrzymaj wszystkie skany</button>
}

function Users() {
  const { data, reload } = useApi<any[]>('/users')
  const roles = useApi<any[]>('/roles')
  const { me } = useAuth()
  const [edit, setEdit] = useState<any>(null)
  return <div className="stack">
    <div className="row"><div className="spacer" /><button className="primary sm" onClick={() => setEdit({ email: '', display_name: '', role_id: roles.data?.find(r => r.name === 'VIEWER')?.id, password: '' })}>Nowy użytkownik</button></div>
    <Panel pad={false}><table className="tbl">
      <thead><tr><th>Użytkownik</th><th>Rola</th><th>Stan</th><th>Ostatnie logowanie</th><th /></tr></thead>
      <tbody>{data?.map(u => <tr key={u.id} className={u.is_active ? '' : 'dim'}>
        <td><b>{u.display_name || u.email}</b><div className="sub">{u.email}</div></td><td><span className="badge">{u.role}</span></td>
        <td className="small">{u.is_active ? (u.locked_until && new Date(u.locked_until) > new Date() ? <span className="badge amber">zablokowany</span> : 'aktywny') : 'wyłączony'}</td>
        <td className="small muted">{ago(u.last_login_at)}</td>
        <td className="right"><button className="ghost sm" onClick={() => setEdit({ ...u, password: '' })}>edytuj</button>{u.id !== me?.id && <button className="ghost sm danger" onClick={async () => { if (confirm('Usunąć użytkownika?')) { await api('/users/' + u.id, { method: 'DELETE' }); reload() } }}>usuń</button>}</td>
      </tr>)}</tbody>
    </table></Panel>
    {edit && <UserForm u={edit} roles={roles.data || []} onClose={() => { setEdit(null); reload() }} />}
  </div>
}

function UserForm({ u, roles, onClose }: { u: any; roles: any[]; onClose: () => void }) {
  const [f, setF] = useState(u)
  const [err, setErr] = useState<any>(null)
  const save = async () => {
    try {
      if (u.id) await api('/users/' + u.id, { method: 'PATCH', body: { display_name: f.display_name, role_id: f.role_id, password: f.password || undefined, is_active: f.is_active } })
      else await api('/users', { body: f })
      onClose()
    } catch (e) { setErr(e) }
  }
  return <Modal title={u.id ? 'Edycja użytkownika' : 'Nowy użytkownik'} onClose={onClose} footer={<><button onClick={onClose}>Anuluj</button><button className="primary" onClick={save}>Zapisz</button></>}>
    <div className="stack">
      {!u.id && <label className="f"><span>E-mail</span><input value={f.email} onChange={e => setF({ ...f, email: e.target.value })} /></label>}
      <label className="f"><span>Nazwa wyświetlana</span><input value={f.display_name} onChange={e => setF({ ...f, display_name: e.target.value })} /></label>
      <label className="f"><span>Rola</span><select value={f.role_id} onChange={e => setF({ ...f, role_id: e.target.value })}>{roles.map(r => <option key={r.id} value={r.id}>{r.name} – {r.description}</option>)}</select></label>
      <label className="f"><span>{u.id ? 'Nowe hasło (opcjonalnie)' : 'Hasło'} – min. 12 znaków</span><input type="password" value={f.password} onChange={e => setF({ ...f, password: e.target.value })} autoComplete="new-password" /></label>
      {u.id && <label className="check"><input type="checkbox" checked={f.is_active} onChange={e => setF({ ...f, is_active: e.target.checked })} />konto aktywne</label>}
      <ErrorNote e={err} />
    </div>
  </Modal>
}

function Roles() {
  const { data, reload } = useApi<any[]>('/roles')
  const perms = useApi<any[]>('/permissions')
  const [edit, setEdit] = useState<any>(null)
  const groups = Array.from(new Set((perms.data || []).map(p => p.group)))
  return <div className="stack">
    <div className="row"><span className="hint">Rola to zbiór uprawnień. Cztery role systemowe odpowiadają wymaganiom (Administracja; Dodawanie, usuwanie, modyfikacja; Modyfikacja i odczyt; Odczyt). Można tworzyć własne.</span><div className="spacer" />
      <button className="primary sm" onClick={() => setEdit({ name: '', description: '', permissions: [] })}>Nowa rola</button></div>
    <Panel pad={false}><div className="table-wrap"><table className="tbl compact">
      <thead><tr><th>Uprawnienie</th>{data?.map(r => <th key={r.id} className="num" style={{ cursor: r.name !== 'ADMIN' ? 'pointer' : undefined }} onClick={() => r.name !== 'ADMIN' && setEdit(r)} title={r.description}>{r.name}<div className="faint" style={{ fontWeight: 400 }}>{r.users} użytk.</div></th>)}</tr></thead>
      <tbody>{groups.map(g => [<tr key={g}><td colSpan={(data?.length || 0) + 1} className="small" style={{ background: 'var(--panel-2)', fontWeight: 600 }}>{g}</td></tr>,
        ...(perms.data || []).filter(p => p.group === g).map(p => <tr key={p.name}><td className="small">{p.label} <span className="faint mono">{p.name}</span></td>
          {data?.map(r => <td key={r.id} className="num">{r.permissions.includes(p.name) ? <span style={{ color: 'var(--green)' }}>●</span> : <span className="faint">·</span>}</td>)}</tr>)])}</tbody>
    </table></div></Panel>
    {edit && <RoleForm r={edit} perms={perms.data || []} onClose={() => { setEdit(null); reload() }} />}
  </div>
}

function RoleForm({ r, perms, onClose }: { r: any; perms: any[]; onClose: () => void }) {
  const [f, setF] = useState({ ...r, permissions: [...r.permissions] })
  const [err, setErr] = useState<any>(null)
  const toggle = (p: string) => setF({ ...f, permissions: f.permissions.includes(p) ? f.permissions.filter((x: string) => x !== p) : [...f.permissions, p] })
  const save = async () => { try { r.id ? await api('/roles/' + r.id, { method: 'PUT', body: f }) : await api('/roles', { body: f }); onClose() } catch (e) { setErr(e) } }
  const del = async () => { try { await api('/roles/' + r.id, { method: 'DELETE' }); onClose() } catch (e) { setErr(e) } }
  const groups = Array.from(new Set(perms.map(p => p.group)))
  return <Modal title={r.id ? 'Rola ' + r.name : 'Nowa rola'} onClose={onClose} wide footer={<>{r.id && !r.is_system && <button className="danger" onClick={del}>Usuń</button>}<div className="spacer" /><button onClick={onClose}>Anuluj</button><button className="primary" onClick={save}>Zapisz</button></>}>
    <div className="stack">
      <div className="form-grid"><label className="f"><span>Nazwa</span><input value={f.name} disabled={r.is_system} onChange={e => setF({ ...f, name: e.target.value })} /></label>
        <label className="f"><span>Opis</span><input value={f.description} onChange={e => setF({ ...f, description: e.target.value })} /></label></div>
      <div className="grid g3">{groups.map(g => <div key={g}><h3>{g}</h3>{perms.filter(p => p.group === g).map(p => <div key={p.name}><label className="check"><input type="checkbox" checked={f.permissions.includes(p.name)} onChange={() => toggle(p.name)} />{p.label}</label></div>)}</div>)}</div>
      <ErrorNote e={err} />
    </div>
  </Modal>
}

function Scope() {
  const { data, reload } = useApi<any>('/scope')
  const [cidr, setCidr] = useState(''), [note, setNote] = useState(''), [ex, setEx] = useState(''), [reason, setReason] = useState('')
  const [err, setErr] = useState<any>(null)
  const add = async () => { try { await api('/scope', { body: { cidr, note } }); setCidr(''); setNote(''); reload() } catch (e) { setErr(e) } }
  const addEx = async () => { try { await api('/exclusions', { body: { value: ex, reason } }); setEx(''); setReason(''); reload() } catch (e) { setErr(e) } }
  return <div className="grid g2">
    <Panel title="Dozwolone zakresy">
      <p className="small muted" style={{ marginTop: 0 }}>Cel spoza tej listy jest odrzucany przy dodawaniu i ponownie sprawdzany przez dispatcher oraz worker. Chroni przed literówką w CIDR i skanowaniem internetu.</p>
      <table className="tbl compact"><tbody>{data?.allow?.map((s: any) => <tr key={s.id}><td className="mono">{s.value}</td><td className="small muted">{s.note}</td><td className="right"><button className="ghost sm danger" onClick={async () => { await api('/scope/' + s.id, { method: 'DELETE' }); reload() }}>usuń</button></td></tr>)}</tbody></table>
      <div className="row" style={{ marginTop: 10 }}><input className="mono" value={cidr} onChange={e => setCidr(e.target.value)} placeholder="10.0.0.0/16" /><input value={note} onChange={e => setNote(e.target.value)} placeholder="opis" style={{ flex: 1 }} /><button className="sm" onClick={add} disabled={!cidr}>Dodaj</button></div>
    </Panel>
    <Panel title="Wykluczenia">
      <p className="small muted" style={{ marginTop: 0 }}>Adresy, których nigdy nie skanujemy (np. sterowniki przemysłowe, urządzenia medyczne, kontrolery domeny).</p>
      <table className="tbl compact"><tbody>{data?.exclusions?.map((s: any) => <tr key={s.id}><td className="mono">{s.value}</td><td className="small muted">{s.note}</td><td className="right"><button className="ghost sm danger" onClick={async () => { await api('/exclusions/' + s.id, { method: 'DELETE' }); reload() }}>usuń</button></td></tr>)}</tbody></table>
      <div className="row" style={{ marginTop: 10 }}><input className="mono" value={ex} onChange={e => setEx(e.target.value)} placeholder="10.0.5.0/24 lub 10.0.0.1" /><input value={reason} onChange={e => setReason(e.target.value)} placeholder="powód" style={{ flex: 1 }} /><button className="sm" onClick={addEx} disabled={!ex}>Dodaj</button></div>
    </Panel>
    <div style={{ gridColumn: '1 / -1' }}><ErrorNote e={err} /></div>
  </div>
}

function DefectDojo() {
  const { data, reload } = useApi<any>('/defectdojo')
  const [f, setF] = useState<any>(null)
  const [token, setToken] = useState('')
  const [test, setTest] = useState<any>(null)
  const [err, setErr] = useState<any>(null)
  const toast = useToast()
  const cfg = f || data?.config
  if (!cfg) return null
  const set = (k: string, v: any) => setF({ ...cfg, [k]: v })
  const save = async () => { try { await api('/defectdojo', { method: 'PUT', body: { ...cfg, token } }); setToken(''); setF(null); reload(); toast('Zapisano – token przechowywany zaszyfrowany') } catch (e) { setErr(e) } }
  const doTest = async () => { setTest(await api('/defectdojo/test', { method: 'POST' })) }
  return <div className="grid g2">
    <Panel title="Połączenie">
      <div className="stack">
        <label className="f"><span>URL instancji</span><input value={cfg.url} onChange={e => set('url', e.target.value)} placeholder="https://defectdojo.example" /></label>
        <label className="f"><span>Token API v2 {cfg.has_token && '(zapisany – wpisz, aby zmienić)'}</span><input type="password" value={token} onChange={e => setToken(e.target.value)} autoComplete="off" /></label>
        <div className="form-grid">
          <label className="f"><span>Product Type</span><input value={cfg.product_type} onChange={e => set('product_type', e.target.value)} /></label>
          <label className="f"><span>Product</span><input value={cfg.product} onChange={e => set('product', e.target.value)} /></label>
          <label className="f"><span>Engagement</span><input value={cfg.engagement} onChange={e => set('engagement', e.target.value)} /></label>
        </div>
        <label className="check"><input type="checkbox" checked={cfg.auto_push} onChange={e => set('auto_push', e.target.checked)} />wysyłaj automatycznie po każdym zakończonym skanie (reimport z close_old_findings)</label>
        <label className="check"><input type="checkbox" checked={cfg.insecure_tls} onChange={e => set('insecure_tls', e.target.checked)} />nie weryfikuj certyfikatu (środowisko testowe)</label>
        <div className="row"><button className="primary" onClick={save}>Zapisz</button><button onClick={doTest}>Test połączenia</button></div>
        <ErrorNote e={err} />
        {test && <div className={'notice ' + (test.ok ? (test.deduplication === false ? 'warn' : 'ok') : 'err')}>{test.ok ? `Połączono jako ${test.user}. Deduplikacja: ${test.deduplication === undefined || test.deduplication === null ? 'nieznana' : test.deduplication ? 'włączona' : 'WYŁĄCZONA'}` : ''} {test.message}</div>}
      </div>
    </Panel>
    <Panel title="Jak działa integracja">
      <ul className="small muted" style={{ margin: 0, paddingLeft: 18, lineHeight: 1.6 }}>
        <li>Każda grupa celów ma swój Test w DefectDojo; pierwsza wysyłka to <code>import-scan</code>, kolejne – <code>reimport-scan</code> do tego samego testu.</li>
        <li>Generic Findings Import deduplikuje po <code>hash_code</code> z tytułu i opisu – dlatego opis jest w pełni deterministyczny (bez dat i wartości sesji).</li>
        <li>Reimport pomija znaleziska oznaczone jako false positive / risk accepted – nie wracają przy kolejnych skanach.</li>
        <li>Przebiegi częściowe nie zamykają starych znalezisk (<code>close_old_findings=false</code>).</li>
      </ul>
      {cfg.tests && Object.keys(cfg.tests).length > 0 && <><h3 style={{ marginTop: 12 }}>Testy w DefectDojo</h3><div className="small mono">{Object.entries(cfg.tests).map(([g, id]: any) => <div key={g}>{g} → test #{id}</div>)}</div></>}
    </Panel>
  </div>
}

function Workers() {
  const { data, reload } = useApi<any[]>('/workers')
  const [name, setName] = useState('')
  const [tok, setTok] = useState<any>(null)
  const gen = async () => { setTok(await api('/workers', { body: { name, vantage: '' } })); setName(''); reload() }
  return <div className="stack">
    <Panel title="Nowy worker">
      <div className="row"><input value={name} onChange={e => setName(e.target.value)} placeholder="np. worker-instytut-a" /><button className="primary sm" onClick={gen} disabled={!name}>Wygeneruj token</button>
        <span className="hint">Worker łączy się z serwerem przez API (nie ma dostępu do bazy ani klucza szyfrowania).</span></div>
      {tok && <div className="notice ok" style={{ marginTop: 10 }}>Token dla <b>{tok.name}</b> (wyświetlany tylko raz): <code>{tok.token}</code> <Copy text={tok.token} />
        <pre className="pre" style={{ marginTop: 8 }}>{`ASI_SERVER_URL=${location.origin} ASI_WORKER_NAME=${tok.name} ASI_WORKER_TOKEN=${tok.token} asi worker`}</pre></div>}
    </Panel>
    <Panel pad={false}>{!data?.length ? <Empty title="Brak workerów" /> : <table className="tbl"><tbody>{data.map(w => <tr key={w.id}>
      <td><span className={'dot ' + (w.online ? 'green' : '')} /><b>{w.name}</b></td><td className="small muted">{ago(w.last_heartbeat)}</td>
      <td className="small">{w.capabilities?.syn ? 'SYN / raw' : 'TCP connect'}</td><td className="small muted">{w.warnings?.join('; ')}</td>
      <td className="right"><button className="ghost sm danger" onClick={async () => { if (confirm('Usunąć worker (unieważnia token)?')) { await api('/workers/' + w.id, { method: 'DELETE' }); reload() } }}>usuń</button></td></tr>)}</tbody></table>}</Panel>
  </div>
}

function Security() {
  const { data, reload } = useApi<any[]>('/encryption')
  const toast = useToast()
  const [busy, setBusy] = useState(false)
  const rotate = async () => {
    if (!confirm('Utworzyć nowy klucz danych i przeszyfrować wszystkie rekordy?')) return
    setBusy(true)
    try { const r = await api('/keys/rotate', { method: 'POST' }); toast(`Przeszyfrowano ${r.reencrypted} rekordów`); reload() } finally { setBusy(false) }
  }
  return <div className="grid g2">
    <Panel title="Klucze" actions={<button className="sm" onClick={rotate} disabled={busy}>{busy ? 'Rotacja…' : 'Rotuj klucz danych'}</button>}>
      <table className="tbl compact"><thead><tr><th>ID</th><th>Cel</th><th>Stan</th><th>Utworzony</th></tr></thead><tbody>{data?.map(k => <tr key={k.id}><td className="mono">{k.id}</td><td>{k.purpose}</td><td>{k.retired_at ? 'wycofany' : k.active ? <span className="badge green">aktywny</span> : 'nieaktywny'}</td><td className="small muted">{dt(k.created_at)}</td></tr>)}</tbody></table>
    </Panel>
    <Panel title="Co jest szyfrowane">
      <ul className="small muted" style={{ margin: 0, paddingLeft: 18, lineHeight: 1.6 }}>
        <li><b>AES-256-GCM:</b> pełne nagłówki, wartości cookies, fragmenty treści, banery, certyfikaty, wyniki skryptów, notatki, token DefectDojo.</li>
        <li><b>Envelope:</b> klucze danych zaszyfrowane kluczem głównym z <code>ASI_MASTER_KEY</code> (poza bazą).</li>
        <li><b>AAD:</b> szyfrogram związany z tabelą, kolumną i rekordem – nie da się go przenieść.</li>
        <li><b>HMAC-SHA256:</b> odciski porównawcze (zmiany, klastry) bez ujawniania wartości.</li>
        <li><b>argon2id:</b> hasła i tokeny workerów; sesje przechowywane jako SHA-256.</li>
        <li>Jawne pozostają metadane potrzebne do filtrowania (IP, port, produkt, wersja, tytuł) – zalecane szyfrowanie wolumenu.</li>
      </ul>
    </Panel>
  </div>
}

function Audit() {
  const [q, setQ] = useState('')
  const { data } = useApi<any[]>('/audit' + qs({ q, limit: 300 }))
  return <div className="stack">
    <div className="row"><SearchBox value={q} onChange={setQ} placeholder="użytkownik, akcja, obiekt…" /></div>
    <Panel pad={false}><table className="tbl compact">
      <thead><tr><th>Kiedy</th><th>Kto</th><th>Akcja</th><th>Obiekt</th><th>Szczegóły</th><th>IP</th></tr></thead>
      <tbody>{data?.map(a => <tr key={a.id}><td className="small nowrap">{dt(a.at)}</td><td className="small">{a.actor}</td><td className="small mono">{a.action}</td>
        <td className="small mono ellipsis" style={{ maxWidth: 220 }}>{a.object} {a.object_id}</td><td className="small muted mono ellipsis" style={{ maxWidth: 360 }}>{JSON.stringify(a.details)}</td><td className="small muted">{a.ip}</td></tr>)}</tbody>
    </table></Panel>
  </div>
}
