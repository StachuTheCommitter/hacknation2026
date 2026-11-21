import { StrictMode, Suspense, lazy, useCallback, useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Navigate, NavLink, Route, Routes, useNavigate } from 'react-router-dom'
import './styles.css'
import { api, setUnauthorizedHandler, useApi, useEvents } from './api'
import { AuthCtx, Me, ToastProvider, useAuth, useToast } from './ui'
import Login from './pages/Login'
import Overview from './pages/Overview'

// Rzadziej używane widoki ładowane na żądanie – pierwszy ekran jest lekki.
const Assets = lazy(() => import('./pages/Assets'))
const Host = lazy(() => import('./pages/Host'))
const Changes = lazy(() => import('./pages/Changes'))
const Scans = lazy(() => import('./pages/Scans'))
const Run = lazy(() => import('./pages/Run'))
const Group = lazy(() => import('./pages/Group'))
const Signatures = lazy(() => import('./pages/Signatures'))
const Findings = lazy(() => import('./pages/Findings'))
const Data = lazy(() => import('./pages/Data'))
const Admin = lazy(() => import('./pages/Admin'))
const Clusters = lazy(() => import('./pages/Clusters'))

function Shell() {
  const { me, can } = useAuth()
  const nav = useNavigate()
  const toast = useToast()
  const kill = useApi<any>('/killswitch')
  useEvents(['killswitch'], kill.reload)
  const logout = async () => { await api('/auth/logout', { method: 'POST' }).catch(() => {}); window.location.href = '/login' }
  const release = async () => {
    await api('/killswitch', { body: { active: false, reason: 'zwolniony z paska' } })
    kill.reload(); toast('Skanowanie wznowione')
  }
  return <div className="shell">
    <aside className="side">
      <div className="brand" onClick={() => nav('/')} style={{ cursor: 'pointer' }}>
        <div className="brand-mark"><svg width="12" height="12" viewBox="0 0 16 16"><path d="M3 13 8 3l5 10" stroke="#fff" strokeWidth="2" fill="none" /></svg></div>
        <div><b>ASI</b><small>Attack Surface Intelligence</small></div>
      </div>
      <nav className="nav">
        <NavLink to="/" end>Przegląd</NavLink>
        <div className="nav-sec">Zasoby</div>
        <NavLink to="/assets/hosts">Hosty</NavLink>
        <NavLink to="/assets/services">Usługi</NavLink>
        <NavLink to="/assets/web">Strony WWW</NavLink>
        <NavLink to="/assets/tech">Technologie</NavLink>
        <NavLink to="/clusters">Grupy podobnych</NavLink>
        <div className="nav-sec">Analiza</div>
        <NavLink to="/changes">Zmiany</NavLink>
        <NavLink to="/findings">Znaleziska</NavLink>
        <NavLink to="/signatures">Sygnatury</NavLink>
        <div className="nav-sec">Operacje</div>
        <NavLink to="/scans">Skany</NavLink>
        <NavLink to="/data">Import i eksport</NavLink>
        {(can('users:manage') || can('settings:manage') || can('audit:read') || can('roles:manage')) && <NavLink to="/admin">Administracja</NavLink>}
      </nav>
      <div className="side-foot">
        <div className="who">{me?.display_name || me?.email}</div>
        <div className="muted" title={me?.role_description}>{me?.role}</div>
        <div className="row" style={{ marginTop: 8 }}><button className="sm" onClick={logout}>Wyloguj</button></div>
      </div>
    </aside>
    <main className="main">
      {kill.data?.active && <div className="kill-banner"><b>Wyłącznik awaryjny aktywny</b> – workery nie otrzymują zadań. {kill.data.reason && `Powód: ${kill.data.reason}.`}
        {can('killswitch:use') && <button onClick={release}>Wznów skanowanie</button>}</div>}
      <Suspense fallback={<div className="page muted">Wczytywanie…</div>}>
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/assets/:tab" element={<Assets />} />
          <Route path="/hosts/:ip" element={<Host />} />
          <Route path="/clusters" element={<Clusters />} />
          <Route path="/changes" element={<Changes />} />
          <Route path="/findings" element={<Findings />} />
          <Route path="/signatures" element={<Signatures />} />
          <Route path="/scans" element={<Scans />} />
          <Route path="/scans/runs/:id" element={<Run />} />
          <Route path="/scans/groups/:id" element={<Group />} />
          <Route path="/data" element={<Data />} />
          <Route path="/admin" element={<Admin />} />
          <Route path="/admin/:tab" element={<Admin />} />
          <Route path="*" element={<div className="page"><h1>Nie znaleziono</h1></div>} />
        </Routes>
      </Suspense>
    </main>
  </div>
}

function App() {
  const [me, setMe] = useState<Me | null | undefined>(undefined)
  const [meta, setMeta] = useState<any>({})
  const refresh = useCallback(() => {
    api<Me>('/auth/me').then(m => { setMe(m); api('/meta').then(setMeta).catch(() => {}) }).catch(() => setMe(null))
  }, [])
  useEffect(() => { refresh(); setUnauthorizedHandler(() => setMe(null)) }, [refresh])
  const perms = new Set(me?.permissions || [])
  const can = (p: string) => perms.has(p)
  if (me === undefined) return null
  return <AuthCtx.Provider value={{ me, can, refresh, meta }}>
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={me ? <Navigate to="/" /> : <Login onLogin={refresh} />} />
        <Route path="*" element={me ? <Shell /> : <Navigate to="/login" />} />
      </Routes>
    </BrowserRouter>
  </AuthCtx.Provider>
}

createRoot(document.getElementById('root')!).render(<StrictMode><ToastProvider><App /></ToastProvider></StrictMode>)
