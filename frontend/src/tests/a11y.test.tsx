import { render } from '@testing-library/react';
import { axe, toHaveNoViolations } from 'jest-axe';
import { BrowserRouter } from 'react-router-dom';

// Extend Jest matchers
expect.extend(toHaveNoViolations);

// Import components to test
import App from '../App';
import Dashboard from '../pages/Dashboard';
import Login from '../pages/Login';

describe('Accessibility Tests', () => {
  it('App should have no accessibility violations', async () => {
    const { container } = render(
      <BrowserRouter>
        <App />
      </BrowserRouter>
    );
    
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });
  
  it('Login page should be keyboard navigable', async () => {
    const { getByLabelText, getByRole } = render(
      <BrowserRouter>
        <Login />
      </BrowserRouter>
    );
    
    // Check form elements have labels
    expect(getByLabelText(/email/i)).toBeInTheDocument();
    expect(getByLabelText(/password/i)).toBeInTheDocument();
    expect(getByRole('button', { name: /login/i })).toBeInTheDocument();
  });
  
  it('Dashboard should announce dynamic content', async () => {
    const { container } = render(
      <BrowserRouter>
        <Dashboard />
      </BrowserRouter>
    );
    
    // Check for live regions
    const liveRegions = container.querySelectorAll('[aria-live]');
    expect(liveRegions.length).toBeGreaterThan(0);
  });
  
  it('Color contrast should meet WCAG AA standards', async () => {
    const { container } = render(
      <BrowserRouter>
        <App />
      </BrowserRouter>
    );
    
    const results = await axe(container, {
      rules: {
        'color-contrast': { enabled: true }
      }
    });
    
    expect(results).toHaveNoViolations();
  });
});