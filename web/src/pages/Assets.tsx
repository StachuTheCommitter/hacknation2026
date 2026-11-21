import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { download, qs, useApi } from '../api'
import { Cat, Conf, Empty, HostLink, Labels, Ms, Pager, Panel, Score, SearchBox, State, Tabs, Top, ago, num, useAuth } from '../ui'

const tabs: [string, string][] = [['hosts', 'Hosty'], ['services', 'Usługi'], ['web', 'Strony WWW'], ['tech', 'Technologie']]
const hints: Record<string, string> = {
  hosts: 'np. 10.77.1, wordpress, cat:admin_panel, tech:nginx, port:8080, label:flapping, tag:prod, score>30, state:inactive, cidr:10.77.3.0/24',
  services: 'np. ssh, product:openssh, port:3306, cat:eol_software, state:suspect',
  web: 'np. grafana, status:401, tech:php, cat:staging',
  tech: 'nazwa technologii lub kategoria (cms, framework, iot)',
}

export default function Assets() {
  const { tab = 'hosts' } = useParams()
  const [sp, setSp] = useSearchParams()
  const nav = useNavigate()
  const q = sp.get('q') || ''
  const [offset, setOffset] = useState(0)
  useEffect(() => setOffset(0), [q, tab])
  const setQ = (v: string) => { const n = new URLSearchParams(sp); v ? n.set('q', v) : n.delete('q'); setSp(n, { replace: true }) }
  const { can } = useAuth()
  return <>
    <Top title="Zasoby">
      <SearchBox value={q} onChange={setQ} placeholder={'Szukaj albo filtruj…   ( / )'} />
      {can('export:use') && tab !== 'tech' && <ExportMenu q={q} />}
    </Top>
    <div className="page">
      <Tabs items={tabs} value={tab} onChange={t => nav(`/assets/${t}${q ? '?q=' + encodeURIComponent(q) : ''}`)} />
      <div className="hint" style={{ marginTop: -6, marginBottom: 10 }}>{hints[tab]}</div>
      {tab === 'hosts' && <Hosts q={q} offset={offset} setOffset={setOffset} />}
      {tab === 'services' && <Services q={q} offset={offset} setOffset={setOffset} />}
      {tab === 'web' && <Web q={q} offset={offset} setOffset={setOffset} />}
      {tab === 'tech' && <Tech q={q} />}
    </div>
  </>
}

function ExportMenu({ q }: { q: string }) {
  const [open, setOpen] = useState(false)
  return <div style={{ position: 'relative' }}>
    <button onClick={() => setOpen(!open)}>Eksport</button>
    {open && <div className="panel" style={{ position: 'absolute', right: 0, top: 34, zIndex: 10, padding: 6, width: 200 }} onMouseLeave={() => setOpen(false)}>
      {['csv', 'json', 'jsonl'].map(f => <button key={f} className="ghost" style={{ width: '100%' }} onClick={() => { download('/export' + qs({ format: f, q })); setOpen(false) }}>{f.toUpperCase()} – bieżący filtr</button>)}
    </div>}
  </div>
}

const LIMIT = 100

function Hosts({ q, offset, setOffset }: { q: string; offset: number; setOffset: (n: number) => void }) {
  const { data, loading } = useApi<any>('/hosts' + qs({ q, limit: LIMIT, offset }))
  const nav = useNavigate()
  if (!data) return <div className="muted">{loading ? 'Wczytywanie…' : ''}</div>
  if (!data.items.length) return <Panel><Empty title={q ? 'Brak wyników dla filtra' : 'Brak hostów'}>{q ? 'Zmień zapytanie albo usuń filtr.' : <>Dodaj cele i uruchom skan w zakładce <Link to="/scans">Skany</Link> albo zaimportuj wyniki.</>}</Empty></Panel>
  return <Panel pad={false}>
    <div className="table-wrap"><table className="tbl">
      <thead><tr><th style={{ width: 52 }}>Ocena</th><th>Adres</th><th>Nazwy</th><th>Stan</th><th>Porty</th><th>Kategorie i technologie</th><th>Grupa</th><th>Ostatnio</th></tr></thead>
      <tbody>{data.items.map((h: any) => <tr key={h.id} className={'click' + (h.state === 'INACTIVE' ? ' dim' : '')} onClick={() => nav('/hosts/' + h.ip)}>
        <td><Score v={h.score} /></td>
        <td><HostLink ip={h.ip} />{h.overrides?.description && <div className="sub ellipsis" style={{ maxWidth: 180 }}>{h.overrides.description}</div>}</td>
        <td className="ellipsis" style={{ maxWidth: 200 }}>{h.hostnames?.join(', ') || <span className="faint">—</span>}</td>
        <td><State s={h.state} /> <Labels l={h.labels} /></td>
        <td className="mono small" style={{ maxWidth: 200 }}>{h.ports?.slice(0, 8).join(', ')}{h.ports?.length > 8 && ` +${h.ports.length - 8}`}</td>
        <td><div className="row tight">{h.categories?.filter((c: string) => !['framework', 'info_disclosure', 'weak_config'].includes(c)).map((c: string) => <Cat key={c} c={c} />)}
          {h.tags?.map((t: string) => <span key={t} className="tag">{t}</span>)}</div>
          <div className="sub">{h.techs?.slice(0, 5).join(', ')}</div></td>
        <td className="small muted">{h.group}</td>
        <td className="small muted nowrap">{ago(h.last_seen)}</td>
      </tr>)}</tbody>
    </table></div>
    <Pager total={data.total} limit={LIMIT} offset={offset} onPage={setOffset} />
  </Panel>
}

function Services({ q, offset, setOffset }: { q: string; offset: number; setOffset: (n: number) => void }) {
  const { data } = useApi<any>('/services' + qs({ q, limit: LIMIT, offset }))
  const nav = useNavigate()
  if (!data) return null
  if (!data.items.length) return <Panel><Empty title="Brak usług" /></Panel>
  return <Panel pad={false}>
    <div className="table-wrap"><table className="tbl">
      <thead><tr><th style={{ width: 52 }}>Ocena</th><th>Usługa</th><th>Rozpoznanie</th><th className="num">Pewność</th><th>Stan</th><th>Kategorie</th><th>Ostatnio</th></tr></thead>
      <tbody>{data.items.map((s: any) => <tr key={s.id} className={'click' + (s.state === 'INACTIVE' ? ' dim' : '')} onClick={() => nav('/hosts/' + s.ip)}>
        <td><Score v={s.score} /></td>
        <td className="nowrap"><span className="mono">{s.ip}</span> <b className="mono">{s.port}</b><span className="faint">/{s.proto}</span></td>
        <td><b>{s.overrides?.product ?? s.product}</b> {s.overrides?.version ?? s.version} <span className="muted">{s.service}</span>
          {s.overrides?.product !== undefined && <span className="badge" title="wartość ustawiona przez analityka">ręcznie</span>}
          {s.nmap_method === 'table' && <div className="sub">nazwa zgadnięta z numeru portu</div>}</td>
        <td className="num"><Conf v={s.confidence} /></td>
        <td><State s={s.state} /> <Labels l={s.labels} /></td>
        <td><div className="row tight">{s.categories?.map((c: string) => <Cat key={c} c={c} />)}</div></td>
        <td className="small muted nowrap">{ago(s.last_seen)}</td>
      </tr>)}</tbody>
    </table></div>
    <Pager total={data.total} limit={LIMIT} offset={offset} onPage={setOffset} />
  </Panel>
}

function Web({ q, offset, setOffset }: { q: string; offset: number; setOffset: (n: number) => void }) {
  const { data } = useApi<any>('/web' + qs({ q, limit: LIMIT, offset }))
  const nav = useNavigate()
  if (!data) return null
  if (!data.items.length) return <Panel><Empty title="Brak stron WWW" /></Panel>
  return <Panel pad={false}>
    <div className="table-wrap"><table className="tbl">
      <thead><tr><th style={{ width: 52 }}>Ocena</th><th>Adres</th><th className="num">Kod</th><th>Tytuł</th><th>Technologie</th><th>Kategorie</th><th>TLS</th><th className="num">Czas</th></tr></thead>
      <tbody>{data.items.map((w: any) => {
        const techs = (w.techs || []) as any[]
        const cats = (w.categories || []) as any[]
        return <tr key={w.id} className={'click' + (w.state === 'INACTIVE' ? ' dim' : '')} onClick={() => nav('/hosts/' + w.ip)}>
          <td><Score v={w.score} /></td>
          <td className="mono small" style={{ maxWidth: 260 }}><div className="ellipsis">{w.url}</div>{w.server && <div className="sub">{w.server}</div>}</td>
          <td className="num"><span className={w.status >= 500 ? 'conflict' : w.status >= 400 ? 'muted' : ''}>{w.status}</span></td>
          <td className="ellipsis" style={{ maxWidth: 240 }} title={w.title}>{w.overrides?.title ?? w.title}</td>
          <td className="small">{techs.slice(0, 4).map((t, i) => <span key={t.name} title={`pewność ${Math.round(t.confidence * 100)}%`}>{i > 0 && ' · '}{t.name}{t.version ? ' ' + t.version : ''}</span>)}</td>
          <td><div className="row tight">{cats.filter(c => c.confidence >= 0.45 && !['info_disclosure', 'weak_config'].includes(c.category)).map(c => <Cat key={c.category} c={c.category} conf={c.confidence} />)}</div></td>
          <td className="small nowrap">{w.tls ? <TLSCell t={w.tls} /> : <span className="faint">—</span>}</td>
          <td className="num small nowrap"><Ms v={w.response_ms} /></td>
        </tr>
      })}</tbody>
    </table></div>
    <Pager total={data.total} limit={LIMIT} offset={offset} onPage={setOffset} />
  </Panel>
}

export function TLSCell({ t }: { t: any }) {
  if (t.expired) return <span className="badge red">wygasł</span>
  if (t.days_left < 30) return <span className="badge amber">{t.days_left} dni</span>
  if (t.self_signed) return <span className="badge amber">self-signed</span>
  return <span className="muted">{t.version || 'TLS'} · {t.days_left} dni</span>
}

function Tech({ q }: { q: string }) {
  const { data } = useApi<any[]>('/technologies' + qs({ q }))
  const nav = useNavigate()
  if (!data) return null
  if (!data.length) return <Panel><Empty title="Brak technologii" /></Panel>
  return <Panel pad={false}>
    <table className="tbl">
      <thead><tr><th>Technologia</th><th>Kategoria</th><th className="num">Hosty</th><th className="num">Wystąpienia</th><th>Wersje</th><th className="num">Śr. pewność</th></tr></thead>
      <tbody>{data.map(t => <tr key={t.name} className="click" onClick={() => nav('/assets/hosts?q=' + encodeURIComponent('tech:' + t.name.split(' ')[0]))}>
        <td><b>{t.name}</b></td><td className="muted">{t.category}</td><td className="num">{num(t.hosts)}</td><td className="num">{num(t.count)}</td>
        <td className="small mono">{t.versions?.slice(0, 6).join(', ')}{t.versions?.length > 6 && ' …'}</td><td className="num"><Conf v={t.avg_confidence} /></td>
      </tr>)}</tbody>
    </table>
  </Panel>
}
