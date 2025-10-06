import { createContext, useContext, useState, useEffect, ReactNode } from 'react';

// Define the shape of the context data
interface AuthContextType {
  isAuthenticated: boolean;
  user: any; // Replace 'any' with a proper User type later
  loading: boolean;
  login: (token: string) => void;
  logout: () => void;
  setUser: (user: any) => void;
}

// Create the context with a default value
const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Create a provider component
export function AuthProvider({ children }: { children: ReactNode }) {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState<any>(null); // Replace 'any' with User type
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check for a token in localStorage on initial load
    const token = localStorage.getItem('authToken');
    if (token) {
      // In a real app, you would validate the token with the backend
      setIsAuthenticated(true);
      setUser({ name: 'Placeholder User' }); // Placeholder, replace with actual user data
    }
    setLoading(false);
  }, []);

  const login = (token: string) => {
    localStorage.setItem('authToken', token);
    setIsAuthenticated(true);
    setUser({ name: 'Placeholder User' }); // Placeholder user
  };

  const logout = () => {
    localStorage.removeItem('authToken');
    setIsAuthenticated(false);
    setUser(null);
  };

  const value = {
    isAuthenticated,
    user,
    loading,
    login,
    logout,
    setUser,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

// Create a custom hook to use the auth context
export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
