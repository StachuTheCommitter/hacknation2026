import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api, qs, useApi, useEvents } from '../api'
import { ChangeType, Empty, HostLink, Panel, Score, SearchBox, Tabs, Top, ago, dt, keyLabel, useAuth, useToast } from '../ui'
import { DiffFields, fmt } from './Host'

const groups: [string, string][] = [
  ['', 'Wszystkie'], ['HOST_NEW,SERVICE_NEW', 'Nowe'], ['HOST_MISSING,SERVICE_MISSING,HOST_GONE,SERVICE_GONE', 'Zniknęły'], ['SERVICE_CHANGED,HTTP_CHANGED,TLS_CHANGED,IDENTITY_CHANGED', 'Zmienione'],
  ['SIGNATURE_MATCH_NEW,SIGNATURE_MATCH_GONE', 'Sygnatury'], ['STATE_FLAPPING,STATE_PERIODIC,HOST_RETURNED,SERVICE_RETURNED', 'Dostępność'],
]

export default function Changes() {
  const [sp, setSp] = useSearchParams()
  const tab = sp.get('tab') || 'feed'
  return <>
    <Top title="Zmiany" />
    <div className="page">
      <Tabs items={[['feed', 'Strumień zmian'], ['diff', 'Porównanie skanów']]} value={tab} onChange={t => { const n = new URLSearchParams(sp); n.set('tab', t); setSp(n) }} />
      {tab === 'feed' ? <Feed /> : <Diff />}
    </div>
  </>
}

function Feed() {
  const [sp, setSp] = useSearchParams()
  const type = sp.get('type') || ''
  const q = sp.get('q') || ''
  const [unacked, setUnacked] = useState(false)
  const [hideBaseline, setHideBaseline] = useState(true)
  const { data, reload } = useApi<any[]>('/changes' + qs({ type, q, unacked, limit: 300, min_priority: hideBaseline ? 1 : -1 }))
  useEvents(['changes'], reload, 1500)
  const { can } = useAuth()
  const toast = useToast()
  const [sel, setSel] = useState<Set<number>>(new Set())
  const set = (k: string, v: string) => { const n = new URLSearchParams(sp); v ? n.set(k, v) : n.delete(k); setSp(n, { replace: true }) }
  const ack = async (ids: number[]) => { await api('/changes/ack', { body: { ids } }); setSel(new Set()); reload(); toast(`Przejrzano: ${ids.length}`) }
  return <div className="stack">
    <div className="row">
      <div className="row tight">{groups.map(([k, l]) => <button key={l} className={'sm' + (type === k ? ' primary' : '')} onClick={() => set('type', k)}>{l}</button>)}</div>
      <div className="spacer" />
      <label className="check"><input type="checkbox" checked={unacked} onChange={e => setUnacked(e.target.checked)} />tylko nieprzejrzane</label>
      <label className="check" title="Pierwszy skan grupy rejestruje wszystko jako nowe – domyślnie ukrywamy te wpisy"><input type="checkbox" checked={hideBaseline} onChange={e => setHideBaseline(e.target.checked)} />ukryj stan początkowy</label>
      <SearchBox value={q} onChange={v => set('q', v)} placeholder="adres, port, opis…" />
    </div>
    {sel.size > 0 && can('results:update') && <div className="row"><button className="primary sm" onClick={() => ack([...sel])}>Oznacz {sel.size} jako przejrzane</button></div>}
    <Panel pad={false}>
      {!data?.length ? <Empty title="Brak zmian">Zmiany pojawiają się po kolejnych przebiegach skanu, imporcie lub ręcznym dodaniu danych.</Empty> :
        <table className="tbl">
          <thead><tr>{can('results:update') && <th style={{ width: 28 }} />}<th style={{ width: 52 }}>Prior.</th><th style={{ width: 140 }}>Typ</th><th>Encja</th><th>Opis</th><th>Grupa</th><th>Kiedy</th></tr></thead>
          <tbody>{data.map(c => <tr key={c.id} className={c.acknowledged_by ? 'dim' : ''}>
            {can('results:update') && <td><input type="checkbox" checked={sel.has(c.id)} onChange={e => { const n = new Set(sel); e.target.checked ? n.add(c.id) : n.delete(c.id); setSel(n) }} /></td>}
            <td><Score v={c.priority} /></td>
            <td><ChangeType t={c.type} /></td>
            <td className="nowrap">{c.host_ip ? <HostLink ip={c.host_ip}>{keyLabel(c.entity_key)}</HostLink> : <span className="mono">{c.entity_key}</span>}</td>
            <td className="small">{c.summary}<DiffFields diff={c.diff} /></td>
            <td className="small muted">{c.group_name}</td>
            <td className="small muted nowrap" title={dt(c.at)}>{ago(c.at)}{c.acknowledged_by && <div>✓ {c.acknowledged_by}</div>}</td>
          </tr>)}</tbody>
        </table>}
    </Panel>
  </div>
}

function Diff() {
  const { data: runs } = useApi<any[]>('/runs?limit=200')
  const [sp, setSp] = useSearchParams()
  const [a, setA] = useState(sp.get('a') || '')
  const [b, setB] = useState(sp.get('b') || '')
  const [filter, setFilter] = useState<'ALL' | 'ADDED' | 'REMOVED' | 'CHANGED'>('ALL')
  const [res, setRes] = useState<any>(null)
  const [err, setErr] = useState('')
  const usable = (runs || []).filter(r => r.status === 'COMPLETED' || r.status === 'SUPERSEDED' || r.status === 'PAUSED_WINDOW' || r.status === 'RUNNING')
  useEffect(() => {
    if (!a && !b && usable.length >= 2) {
      const scanner = usable.filter(r => r.source === 'scanner')
      const pick = scanner.length >= 2 ? scanner : usable
      setB(pick[0].id); const same = pick.slice(1).find(r => r.group_id === pick[0].group_id); setA((same || pick[1]).id)
    }
  }, [runs])
  useEffect(() => {
    if (!a || !b || a === b) return
    setErr('')
    const n = new URLSearchParams(sp); n.set('a', a); n.set('b', b); setSp(n, { replace: true })
    api('/runs/' + a + '/diff/' + b).then(setRes).catch(e => setErr(e.message))
  }, [a, b])
  const label = (r: any) => `${dt(r.created_at)} · ${r.group_name || r.source} · ${r.mode}${r.note ? ' · ' + r.note.slice(0, 40) : ''}`
  const items = (res?.items || []).filter((i: any) => filter === 'ALL' || i.kind === filter)
  return <div className="stack">
    <Panel>
      <div className="row">
        <label className="f" style={{ flex: 1 }}><span>Przebieg A (wcześniejszy)</span><select value={a} onChange={e => setA(e.target.value)}><option value="">— wybierz —</option>{usable.map(r => <option key={r.id} value={r.id}>{label(r)}</option>)}</select></label>
        <label className="f" style={{ flex: 1 }}><span>Przebieg B (późniejszy)</span><select value={b} onChange={e => setB(e.target.value)}><option value="">— wybierz —</option>{usable.map(r => <option key={r.id} value={r.id}>{label(r)}</option>)}</select></label>
      </div>
    </Panel>
    {err && <div className="notice err">{err}</div>}
    {res && <>
      <div className="row">
        {(['ALL', 'ADDED', 'REMOVED', 'CHANGED'] as const).map(k => <button key={k} className={'sm' + (filter === k ? ' primary' : '')} onClick={() => setFilter(k)}>
          {{ ALL: 'Wszystko', ADDED: 'Dodane', REMOVED: 'Usunięte', CHANGED: 'Zmienione' }[k]} {k !== 'ALL' && <b>{res.counts[k]}</b>}</button>)}
        <div className="spacer" />
        <span className="hint">wspólne pokrycie: {res.common_addresses.toLocaleString('pl-PL')} adresów × {res.common_tcp_ports} portów TCP</span>
      </div>
      {res.note && <div className="notice">{res.note}</div>}
      <Panel pad={false}>
        {!items.length ? <Empty title="Brak różnic">Na wspólnym pokryciu oba przebiegi widzą to samo.</Empty> :
          <table className="tbl">
            <thead><tr><th style={{ width: 100 }}>Zmiana</th><th>Encja</th><th>Szczegóły</th></tr></thead>
            <tbody>{items.map((i: any) => <tr key={i.key + i.kind}>
              <td><span className={'badge ' + (i.kind === 'ADDED' ? 'blue' : i.kind === 'REMOVED' ? '' : 'amber')}>{{ ADDED: 'dodane', REMOVED: 'usunięte', CHANGED: 'zmienione' }[i.kind as string]}</span></td>
              <td className="nowrap"><HostLink ip={i.ip}>{keyLabel(i.key)}</HostLink> <span className="faint small">{i.entity_type}</span></td>
              <td className="small">{i.kind === 'CHANGED' ? <div className="diffval">{i.fields.map((f: any) => <div key={f.field}><span className="muted">{f.field}:</span> <span className="old">{fmt(f.old)}</span> → <span className="new">{fmt(f.new)}</span></div>)}</div> : <span className="muted">{i.summary}</span>}</td>
            </tr>)}</tbody>
          </table>}
      </Panel>
    </>}
    {!res && !err && <Empty title="Wybierz dwa przebiegi">Porównanie obejmuje tylko adresy i porty przeskanowane w obu przebiegach, więc przerwany skan nie generuje fałszywych „zniknięć”.</Empty>}
  </div>
}


