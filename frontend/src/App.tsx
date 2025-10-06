import { BrowserRouter as Router, Routes, Route } from "react-router-dom"
import { ThemeProvider } from "./components/ui/theme-provider"
import { AuthProvider } from "./contexts/AuthContext"
import { Toaster } from "./components/ui/toaster"
import { ProtectedRoute } from "./components/ProtectedRoute"
import { ErrorBoundary } from "react-error-boundary"
import Dashboard from "./pages/Dashboard"
import Settings from "./pages/Settings"
import Login from "./pages/Login"
import Home from "./pages/Home"

function ErrorFallback({error}: {error: Error}) {
  return (
    <div style={{padding: "40px", color: "red"}}>
      <h1>❌ Ошибка загрузки компонента</h1>
      <pre style={{background: "#f5f5f5", padding: "10px", overflow: "auto"}}>
        {error.message}
      </pre>
      <button onClick={() => window.location.href = "/"}>На главную</button>
    </div>
  )
}

function App() {
  return (
    <AuthProvider>
      <ThemeProvider defaultTheme="light" storageKey="ui-theme">
        <Router>
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/login" element={<Login />} />
            <Route path="/dashboard" element={
              <ProtectedRoute>
                <ErrorBoundary FallbackComponent={ErrorFallback}>
                  <Dashboard />
                </ErrorBoundary>
              </ProtectedRoute>
            } />
            <Route path="/settings" element={
              <ProtectedRoute>
                <ErrorBoundary FallbackComponent={ErrorFallback}>
                  <Settings />
                </ErrorBoundary>
              </ProtectedRoute>
            } />
            <Route path="*" element={<div style={{padding: "20px"}}>404</div>} />
          </Routes>
        </Router>
        <Toaster />
      </ThemeProvider>
    </AuthProvider>
  )
}

export default App
