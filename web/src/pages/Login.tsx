import { FormEvent, useState } from 'react'
import { api } from '../api'

export default function Login({ onLogin }: { onLogin: () => void }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const submit = async (e?: FormEvent, em = email, pw = password) => {
    e?.preventDefault()
    setBusy(true); setErr('')
    try { await api('/auth/login', { body: { email: em, password: pw } }); onLogin() }
    catch (x: any) { setErr(x.message) }
    finally { setBusy(false) }
  }
  const demo = (who: string) => { setEmail(who + '@lab'); setPassword('demo-password-' + who); submit(undefined, who + '@lab', 'demo-password-' + who) }
  return <div className="login">
    <form className="card" onSubmit={submit}>
      <h1>Attack Surface Intelligence</h1>
      <p className="muted" style={{ marginTop: 0 }}>Centrum Bezpieczeństwa Informacji AGH</p>
      <div className="stack">
        <label className="f"><span>E-mail</span><input autoFocus value={email} onChange={e => setEmail(e.target.value)} autoComplete="username" /></label>
        <label className="f"><span>Hasło</span><input type="password" value={password} onChange={e => setPassword(e.target.value)} autoComplete="current-password" /></label>
        {err && <div className="notice err">{err}</div>}
        <button className="primary" disabled={busy || !email || !password} style={{ width: '100%', justifyContent: 'center' }}>{busy ? 'Logowanie…' : 'Zaloguj'}</button>
      </div>
      <div className="demo">Konta demonstracyjne (jeśli włączone):<br />
        {['admin', 'editor', 'modifier', 'viewer'].map(w => <button type="button" key={w} className="sm" onClick={() => demo(w)}>{w}</button>)}
      </div>
    </form>
  </div>
}
