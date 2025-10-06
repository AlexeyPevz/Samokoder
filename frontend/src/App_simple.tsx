import { BrowserRouter as Router, Routes, Route } from "react-router-dom"
import { ThemeProvider } from "./components/ui/theme-provider"
import { Toaster } from "./components/ui/toaster"
import { AuthProvider } from "./contexts/AuthContext"
import { ProtectedRoute } from "./components/ProtectedRoute"
import { Layout } from "./components/Layout"
import { SkipLinks } from "./components/accessibility/SkipLink"
import { ScreenReaderSupport } from "./components/accessibility/ScreenReaderSupport"
import { useCommonShortcuts } from "./hooks/useKeyboardShortcuts"

// Прямые импорты вместо lazy
import Home from "./pages/Home"
import Dashboard from "./pages/Dashboard"
import Workspace from "./pages/Workspace"
import Settings from "./pages/Settings"
import Login from "./pages/Login"
import Register from "./pages/Register"
import BlankPage from "./pages/BlankPage"
import BrandShowcase from "./pages/BrandShowcase"

import "./styles/accessibility.css"

function App() {
  useCommonShortcuts()
  
  return (
  <AuthProvider>
    <ThemeProvider defaultTheme="light" storageKey="ui-theme">
      <Router>
        <SkipLinks />
        <ScreenReaderSupport />
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/" element={<Home />} />
          <Route path="/" element={<ProtectedRoute> <Layout /> </ProtectedRoute>}>
            <Route path="dashboard" element={<Dashboard />} />
            <Route path="workspace/:projectId" element={<Workspace />} />
            <Route path="settings" element={<Settings />} />
            <Route path="brand" element={<BrandShowcase />} />
          </Route>
          <Route path="*" element={<BlankPage />} />
        </Routes>
      </Router>
      <Toaster />
    </ThemeProvider>
  </AuthProvider>
  )
}

export default App
