import { lazy } from 'react';

// Lazy load pages for better code splitting
export const LazyHome = lazy(() => import('./Home'));
export const LazyDashboard = lazy(() => import('./Dashboard'));
export const LazyWorkspace = lazy(() => import('./Workspace'));
export const LazySettings = lazy(() => import('./Settings'));
export const LazyLogin = lazy(() => import('./Login'));
export const LazyRegister = lazy(() => import('./Register'));
export const LazyBlankPage = lazy(() => import('./BlankPage'));

// Lazy load heavy components
export const LazyChatInterface = lazy(() => import('../components/workspace/ChatInterface'));
export const LazyProjectPreview = lazy(() => import('../components/workspace/ProjectPreview'));
export const LazyTemplateGallery = lazy(() => import('../components/home/TemplateGallery'));
export const LazyBenefitsSection = lazy(() => import('../components/home/BenefitsSection'));