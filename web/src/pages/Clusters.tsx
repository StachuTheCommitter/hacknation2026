import { useSearchParams } from 'react-router-dom'
import { api, useApi } from '../api'
import { Empty, HostLink, Panel, Score, Top, useAuth, useToast } from '../ui'
import { useState } from 'react'

export default function Clusters() {
  const [sp, setSp] = useSearchParams()
  const key = sp.get('key')
  const { data } = useApi<any[]>('/clusters')
  const detail = useApi<any>(key ? '/clusters/' + key : null)
  const { can } = useAuth()
  const toast = useToast()
  const [tag, setTag] = useState('')
  const tagAll = async () => {
    const keys = detail.data.members.map((m: any) => m.ip)
    await api('/tags', { body: { entity_type: 'host', keys, tag } }); toast(`Otagowano ${keys.length} hostów`); setTag('')
  }
  return <>
    <Top title="Grupy podobnych usług" />
    <div className="page">
      <p className="hint" style={{ marginTop: 0 }}>Endpointy WWW o tej samej faviconie, tytule, nagłówku Server i technologiach. Przy dużej sieci jedna grupa zastępuje dziesiątki wierszy, a wersje odstające od większości są wyróżnione.</p>
      <div className="grid g2">
        <Panel pad={false}>{!data?.length ? <Empty title="Brak grup">Grupy pojawią się, gdy co najmniej dwa endpointy będą wyglądać tak samo.</Empty> :
          <table className="tbl"><thead><tr><th className="num">Liczba</th><th>Tytuł / serwer</th><th>Technologie</th><th>Ocena</th></tr></thead>
            <tbody>{data.map(c => <tr key={c.key} className="click" onClick={() => setSp({ key: c.key })} style={c.key === key ? { background: 'var(--accent-soft)' } : undefined}>
              <td className="num"><b>{c.count}</b></td><td><div className="ellipsis" style={{ maxWidth: 260 }}>{c.title || <span className="faint">bez tytułu</span>}</div><div className="sub">{c.server}{c.favicon && ` · favicon ${c.favicon}`}</div></td>
              <td className="small">{c.techs?.slice(0, 4).join(', ')}</td><td><Score v={c.max_score} /></td></tr>)}</tbody></table>}
        </Panel>
        {key && detail.data && <Panel title={`${detail.data.count} × ${detail.data.title || detail.data.server || 'grupa'}`} actions={can('results:update') && <div className="row tight"><input value={tag} onChange={e => setTag(e.target.value)} placeholder="tag dla wszystkich" style={{ minHeight: 24, height: 24 }} /><button className="sm" disabled={!tag} onClick={tagAll}>Otaguj</button></div>} pad={false}>
          <table className="tbl compact"><tbody>{detail.data.members.map((m: any) => <tr key={m.key}>
            <td><HostLink ip={m.ip} /></td><td className="mono small ellipsis" style={{ maxWidth: 220 }}>{m.url}</td>
            <td className="small">{m.versions?.join(', ')}{m.outlier && <span className="badge amber" style={{ marginLeft: 6 }}>odstaje</span>}</td><td><Score v={m.score} /></td></tr>)}</tbody></table>
        </Panel>}
      </div>
    </div>
  </>
}
