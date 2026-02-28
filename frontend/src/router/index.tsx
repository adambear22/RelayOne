import { Spin } from 'antd'
import { BrowserRouter, Navigate, Outlet, Route, Routes, useLocation } from 'react-router-dom'

import AppShell from '../components/AppShell'
import { useAuth } from '../hooks/useAuth'
import AdminPage from '../pages/AdminPage'
import CodesPage from '../pages/CodesPage'
import DashboardPage from '../pages/DashboardPage'
import LoginPage from '../pages/LoginPage'
import MaintenancePage from '../pages/MaintenancePage'
import NodesPage from '../pages/NodesPage'
import NotFoundPage from '../pages/NotFoundPage'
import ProfilePage from '../pages/ProfilePage'
import RulesPage from '../pages/RulesPage'
import TelegramCallbackPage from '../pages/TelegramCallbackPage'
import TrafficPage from '../pages/TrafficPage'
import VIPPage from '../pages/VIPPage'

function LoadingGate() {
  return (
    <div style={{ minHeight: '100vh', display: 'grid', placeItems: 'center' }}>
      <Spin size="large" />
    </div>
  )
}

function PublicOnlyRoute() {
  const { isAuthenticated, bootstrapped } = useAuth()
  if (!bootstrapped) {
    return <LoadingGate />
  }
  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />
  }
  return <Outlet />
}

function ProtectedRoute() {
  const location = useLocation()
  const { user, isAuthenticated, bootstrapped, maintenanceMode } = useAuth()

  if (!bootstrapped) {
    return <LoadingGate />
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location.pathname }} replace />
  }

  if (maintenanceMode && user?.role !== 'admin' && location.pathname !== '/maintenance') {
    return <Navigate to="/maintenance" replace />
  }

  return <Outlet />
}

function AdminRoute() {
  const { user } = useAuth()
  if (user?.role !== 'admin') {
    return <Navigate to="/dashboard" replace />
  }
  return <Outlet />
}

export default function AppRouter() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<PublicOnlyRoute />}>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/auth/telegram/callback" element={<TelegramCallbackPage />} />
        </Route>

        <Route path="/maintenance" element={<MaintenancePage />} />

        <Route element={<ProtectedRoute />}>
          <Route element={<AppShell />}>
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/nodes/*" element={<NodesPage />} />
            <Route path="/rules/*" element={<RulesPage />} />
            <Route path="/traffic/*" element={<TrafficPage />} />
            <Route path="/vip/*" element={<VIPPage />} />
            <Route path="/codes/*" element={<CodesPage />} />
            <Route path="/profile" element={<ProfilePage />} />

            <Route element={<AdminRoute />}>
              <Route path="/admin/*" element={<AdminPage />} />
            </Route>
          </Route>
        </Route>

        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </BrowserRouter>
  )
}
