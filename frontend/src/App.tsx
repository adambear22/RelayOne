import { useEffect } from 'react'

import { useAuthBootstrap } from './hooks/useAuth'
import AppRouter from './router'
import { useSSEStore } from './stores/sse'

function AppBootstrap() {
  useAuthBootstrap()

  const connect = useSSEStore((state) => state.connect)
  const disconnect = useSSEStore((state) => state.disconnect)

  useEffect(() => {
    connect()
    return () => {
      disconnect()
    }
  }, [connect, disconnect])

  return null
}

export default function App() {
  return (
    <>
      <AppBootstrap />
      <AppRouter />
    </>
  )
}
