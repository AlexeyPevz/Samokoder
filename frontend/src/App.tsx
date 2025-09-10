import { BrowserRouter as Router, Routes, Route } from "react-router-dom"
import { ThemeProvider } from "./components/ui/theme-provider"
import { Toaster } from "./components/ui/toaster"
import { AuthProvider } from "./contexts/AuthContext"
import { ProtectedRoute } from "./components/ProtectedRoute"
import { Layout } from "./components/Layout"
import { SkipLinks } from "./components/accessibility/SkipLink"
import { ScreenReaderSupport } from "./components/accessibility/ScreenReaderSupport"
import { useCommonShortcuts } from "./hooks/useKeyboardShortcuts"
import { LazyWrapper } from "./components/LazyWrapper"
import { 
  LazyHome, 
  LazyDashboard, 
  LazyWorkspace, 
  LazySettings, 
  LazyLogin, 
  LazyRegister, 
  LazyBlankPage 
} from "./pages/LazyPages"
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
          <Route 
            path="/login" 
            element={
              <LazyWrapper>
                <LazyLogin />
              </LazyWrapper>
            } 
          />
          <Route 
            path="/register" 
            element={
              <LazyWrapper>
                <LazyRegister />
              </LazyWrapper>
            } 
          />
          <Route path="/" element={<ProtectedRoute> <Layout /> </ProtectedRoute>}>
            <Route 
              index 
              element={
                <LazyWrapper>
                  <LazyHome />
                </LazyWrapper>
              } 
            />
            <Route 
              path="dashboard" 
              element={
                <LazyWrapper>
                  <LazyDashboard />
                </LazyWrapper>
              } 
            />
            <Route 
              path="workspace/:projectId" 
              element={
                <LazyWrapper>
                  <LazyWorkspace />
                </LazyWrapper>
              } 
            />
            <Route 
              path="settings" 
              element={
                <LazyWrapper>
                  <LazySettings />
                </LazyWrapper>
              } 
            />
          </Route>
          <Route 
            path="*" 
            element={
              <LazyWrapper>
                <LazyBlankPage />
              </LazyWrapper>
            } 
          />
        </Routes>
      </Router>
      <Toaster />
    </ThemeProvider>
  </AuthProvider>
  )
}

export default App