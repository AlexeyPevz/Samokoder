import { lazy } from 'react';

// Lazy load pages for better code splitting with error boundaries
export const LazyHome = lazy(() => 
  import('./Home').catch(() => ({
    default: () => <div>Ошибка загрузки главной страницы</div>
  }))
);

export const LazyDashboard = lazy(() => 
  import('./Dashboard').catch(() => ({
    default: () => <div>Ошибка загрузки дашборда</div>
  }))
);

export const LazyWorkspace = lazy(() => 
  import('./Workspace').catch(() => ({
    default: () => <div>Ошибка загрузки рабочего пространства</div>
  }))
);

export const LazySettings = lazy(() => 
  import('./Settings').catch(() => ({
    default: () => <div>Ошибка загрузки настроек</div>
  }))
);

export const LazyLogin = lazy(() => 
  import('./Login').catch(() => ({
    default: () => <div>Ошибка загрузки страницы входа</div>
  }))
);

export const LazyRegister = lazy(() => 
  import('./Register').catch(() => ({
    default: () => <div>Ошибка загрузки страницы регистрации</div>
  }))
);

export const LazyBlankPage = lazy(() => 
  import('./BlankPage').catch(() => ({
    default: () => <div>Ошибка загрузки страницы</div>
  }))
);

// Lazy load heavy components with preloading hints
export const LazyChatInterface = lazy(() => 
  import('../components/workspace/ChatInterface').catch(() => ({
    default: () => <div>Ошибка загрузки чата</div>
  }))
);

export const LazyProjectPreview = lazy(() => 
  import('../components/workspace/ProjectPreview').catch(() => ({
    default: () => <div>Ошибка загрузки превью проекта</div>
  }))
);

export const LazyTemplateGallery = lazy(() => 
  import('../components/home/TemplateGallery').catch(() => ({
    default: () => <div>Ошибка загрузки галереи шаблонов</div>
  }))
);

export const LazyBenefitsSection = lazy(() => 
  import('../components/home/BenefitsSection').catch(() => ({
    default: () => <div>Ошибка загрузки секции преимуществ</div>
  }))
);

// Preload critical components for better perceived performance
export const preloadCriticalComponents = () => {
  // Preload components that are likely to be needed soon
  import('./Home');
  import('./Dashboard');
};