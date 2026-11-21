import { useState } from 'react'
import { api, useApi } from '../api'
import { Empty, ErrorNote, Modal, Panel, useAuth, useToast } from '../ui'

export default function Profiles() {
  const { data, reload } = useApi<any[]>('/profiles')
  const { can, meta } = useAuth()
  const [edit, setEdit] = useState<any>(null)
  if (!data) return null
  return <div className="stack">
    <div className="row"><span className="hint">Profil określa porty, sondy discovery, intensywność identyfikacji i sprawdzane ścieżki HTTP. Przebieg zapamiętuje kopię profilu z chwili startu.</span><div className="spacer" />
      {can('config:create') && <button className="sm" onClick={() => setEdit({ name: '', config: meta.default_profile })}>Nowy profil</button>}</div>
    <Panel pad={false}>
      {!data.length ? <Empty title="Brak profili" /> : <table className="tbl">
        <thead><tr><th>Nazwa</th><th>Porty TCP</th><th className="num">Liczba</th><th>UDP</th><th>Discovery / porty</th><th>nmap -sV</th><th>HTTP</th><th /></tr></thead>
        <tbody>{data.map(p => <tr key={p.id}>
          <td><b>{p.name}</b></td><td className="mono small">{p.config.tcp_ports}</td><td className="num">{p.ports}</td><td className="mono small">{p.config.udp_ports || '—'}</td>
          <td className="small">{p.config.discovery_engine} / {p.config.portscan_engine}{p.config.portscan_scope === 'all' && ' (wszystkie adresy)'}</td>
          <td className="small">intensywność {p.config.nmap_intensity}</td><td className="small">{p.config.http_enabled ? `${p.config.prober_paths?.length} ścieżek` : 'wyłączone'}</td>
          <td className="right">{can('config:update') && <button className="ghost sm" onClick={() => setEdit(p)}>edytuj</button>}</td>
        </tr>)}</tbody>
      </table>}
    </Panel>
    {edit && <ProfileForm p={edit} onClose={() => { setEdit(null); reload() }} />}
  </div>
}

function ProfileForm({ p, onClose }: { p: any; onClose: () => void }) {
  const [name, setName] = useState(p.name)
  const [c, setC] = useState<any>({ ...p.config, prober_paths_text: (p.config.prober_paths || []).join('\n'), retry_text: (p.config.retry_delays_sec || []).join(', ') })
  const [err, setErr] = useState<any>(null)
  const { can } = useAuth()
  const toast = useToast()
  const set = (k: string, v: any) => setC({ ...c, [k]: v })
  const save = async () => {
    const config = { ...c, nmap_intensity: +c.nmap_intensity, retries: +c.retries, prober_paths: c.prober_paths_text.split('\n').map((s: string) => s.trim()).filter(Boolean),
      retry_delays_sec: c.retry_text.split(',').map((s: string) => +s.trim()).filter((n: number) => n > 0) }
    delete config.prober_paths_text; delete config.retry_text
    try { p.id ? await api('/profiles/' + p.id, { method: 'PUT', body: { name, config } }) : await api('/profiles', { body: { name, config } }); toast('Zapisano profil'); onClose() } catch (e) { setErr(e) }
  }
  const del = async () => { if (!confirm('Usunąć profil?')) return; try { await api('/profiles/' + p.id, { method: 'DELETE' }); onClose() } catch (e) { setErr(e) } }
  return <Modal title={p.id ? 'Edycja profilu' : 'Nowy profil'} onClose={onClose} wide footer={<>{p.id && can('config:delete') && <button className="danger" onClick={del}>Usuń</button>}<div className="spacer" /><button onClick={onClose}>Anuluj</button><button className="primary" onClick={save}>Zapisz</button></>}>
    <div className="stack">
      <label className="f"><span>Nazwa</span><input value={name} onChange={e => setName(e.target.value)} /></label>
      <div className="form-grid">
        <label className="f"><span>Porty TCP (np. top-1000,8291)</span><input className="mono" value={c.tcp_ports} onChange={e => set('tcp_ports', e.target.value)} /></label>
        <label className="f"><span>Porty UDP (maks. 50)</span><input className="mono" value={c.udp_ports} onChange={e => set('udp_ports', e.target.value)} placeholder="np. 53,123,1900" /></label>
        <label className="f"><span>Silnik discovery</span><select value={c.discovery_engine} onChange={e => set('discovery_engine', e.target.value)}><option value="nmap">nmap -sn</option><option value="naabu">naabu -sn</option><option value="none">brak (traktuj wszystkie jako żywe)</option></select></label>
        <label className="f"><span>Sondy SYN (porty)</span><input className="mono" value={c.discovery_tcp_syn} onChange={e => set('discovery_tcp_syn', e.target.value)} /></label>
        <label className="f"><span>Sondy ACK (porty)</span><input className="mono" value={c.discovery_tcp_ack} onChange={e => set('discovery_tcp_ack', e.target.value)} /></label>
        <label className="f"><span>Silnik skanu portów</span><select value={c.portscan_engine} onChange={e => set('portscan_engine', e.target.value)}><option value="naabu">naabu (SYN)</option><option value="nmap">nmap</option></select></label>
        <label className="f"><span>Zakres skanu portów</span><select value={c.portscan_scope} onChange={e => set('portscan_scope', e.target.value)}><option value="alive">tylko żywe hosty</option><option value="all">wszystkie adresy (-Pn)</option></select></label>
        <label className="f"><span>Intensywność nmap -sV (1–9)</span><input type="number" min={1} max={9} value={c.nmap_intensity} onChange={e => set('nmap_intensity', e.target.value)} /></label>
        <label className="f"><span>Ponowienia pakietów</span><input type="number" min={0} max={5} value={c.retries} onChange={e => set('retries', e.target.value)} /></label>
        <label className="f"><span>Powtórne pomiary (s, po przecinku)</span><input value={c.retry_text} onChange={e => set('retry_text', e.target.value)} /></label>
      </div>
      <div className="row">
        <label className="check"><input type="checkbox" checked={c.discovery_icmp} onChange={e => set('discovery_icmp', e.target.checked)} />sondy ICMP</label>
        <label className="check"><input type="checkbox" checked={c.http_enabled} onChange={e => set('http_enabled', e.target.checked)} />fingerprinting HTTP</label>
        <label className="check"><input type="checkbox" checked={c.active_signatures} onChange={e => set('active_signatures', e.target.checked)} />sygnatury aktywne (GET ścieżek)</label>
        <label className="check"><input type="checkbox" checked={c.resolve_ptr} onChange={e => set('resolve_ptr', e.target.checked)} />reverse DNS</label>
        <label className="check"><input type="checkbox" checked={c.skip_edge_addresses} onChange={e => set('skip_edge_addresses', e.target.checked)} />pomijaj .0 i .255</label>
      </div>
      <div className="form-grid">
        <label className="f"><span>Skrypty nmap (dozwolone: banner, ssl-cert, ssh-hostkey, http-title)</span>
          <input value={(c.nmap_scripts || []).join(',')} onChange={e => set('nmap_scripts', e.target.value.split(',').map((s: string) => s.trim()).filter(Boolean))} /></label>
      </div>
      <label className="f"><span>Ścieżki sprawdzane metodą GET (jedna na linię – bez logowania, bez parametrów)</span><textarea className="code" rows={6} value={c.prober_paths_text} onChange={e => set('prober_paths_text', e.target.value)} /></label>
      <ErrorNote e={err} />
    </div>
  </Modal>
}
