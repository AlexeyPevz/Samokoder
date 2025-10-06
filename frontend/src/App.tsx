import { BrowserRouter as Router, Routes, Route } from "react-router-dom"
import { Suspense, lazy } from "react"
import { ThemeProvider } from "./components/ui/theme-provider"
import { AuthProvider } from "./contexts/AuthContext"
import { Toaster } from "./components/ui/toaster"
import { ProtectedRoute } from "./components/ProtectedRoute"
import { ErrorBoundary } from "react-error-boundary"

// Lazy load all pages for optimal code splitting
const Home = lazy(() => import("./pages/Home"))
const Dashboard = lazy(() => import("./pages/Dashboard"))
const Settings = lazy(() => import("./pages/Settings"))
const Login = lazy(() => import("./pages/Login"))
const Workspace = lazy(() => import("./pages/Workspace"))
const BrandShowcase = lazy(() => import("./pages/BrandShowcase"))
const BrandTest = lazy(() => import("./pages/BrandTest"))

// Loading fallback component
function LoadingFallback() {
  return (
    <div style={{
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      minHeight: "100vh",
      fontSize: "18px",
      color: "#666"
    }}>
      <div className="loading-spinner" aria-label="Loading page"></div>
    </div>
  )
}

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
          <ErrorBoundary FallbackComponent={ErrorFallback}>
            <Suspense fallback={<LoadingFallback />}>
              <Routes>
                <Route path="/" element={<Home />} />
                <Route path="/login" element={<Login />} />
                <Route path="/dashboard" element={
                  <ProtectedRoute>
                    <Dashboard />
                  </ProtectedRoute>
                } />
                <Route path="/workspace/:id" element={
                  <ProtectedRoute>
                    <Workspace />
                  </ProtectedRoute>
                } />
                <Route path="/settings" element={
                  <ProtectedRoute>
                    <Settings />
                  </ProtectedRoute>
                } />
                <Route path="/brand" element={<BrandShowcase />} />
                <Route path="/brand-test" element={<BrandTest />} />
                <Route path="*" element={<div style={{padding: "20px"}}>404</div>} />
              </Routes>
            </Suspense>
          </ErrorBoundary>
        </Router>
        <Toaster />
      </ThemeProvider>
    </AuthProvider>
  )
}

export default App
