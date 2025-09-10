/**
 * Скрипт для измерения Core Web Vitals до и после оптимизации
 */

// Импорт web-vitals библиотеки
import { getCLS, getFID, getFCP, getLCP, getTTFB, getINP } from 'web-vitals'

// Конфигурация для измерения
const VITALS_CONFIG = {
  // Пороги для Core Web Vitals
  thresholds: {
    LCP: { good: 2500, needsImprovement: 4000 },
    INP: { good: 200, needsImprovement: 500 },
    CLS: { good: 0.1, needsImprovement: 0.25 }
  },
  
  // Настройки отправки данных
  sendToAnalytics: true,
  analyticsEndpoint: '/api/analytics/web-vitals',
  
  // Настройки отладки
  debug: process.env.NODE_ENV === 'development'
}

// Функция для отправки метрик в аналитику
function sendToAnalytics(metric) {
  if (!VITALS_CONFIG.sendToAnalytics) return
  
  const payload = {
    name: metric.name,
    value: metric.value,
    delta: metric.delta,
    id: metric.id,
    navigationType: metric.navigationType,
    timestamp: Date.now(),
    url: window.location.href,
    userAgent: navigator.userAgent,
    connection: navigator.connection ? {
      effectiveType: navigator.connection.effectiveType,
      downlink: navigator.connection.downlink,
      rtt: navigator.connection.rtt
    } : null
  }
  
  // Отправка через fetch API
  fetch(VITALS_CONFIG.analyticsEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload)
  }).catch(error => {
    if (VITALS_CONFIG.debug) {
      console.warn('Failed to send web vitals:', error)
    }
  })
}

// Функция для логирования метрик
function logMetric(metric) {
  const { name, value, delta, id } = metric
  const threshold = VITALS_CONFIG.thresholds[name]
  
  let status = 'unknown'
  if (threshold) {
    if (value <= threshold.good) {
      status = 'good'
    } else if (value <= threshold.needsImprovement) {
      status = 'needs-improvement'
    } else {
      status = 'poor'
    }
  }
  
  const logMessage = `[Web Vitals] ${name}: ${value.toFixed(2)}${getUnit(name)} (${status})`
  
  if (VITALS_CONFIG.debug) {
    console.log(logMessage, {
      metric,
      threshold,
      status
    })
  }
  
  // Отправка в аналитику
  sendToAnalytics(metric)
  
  // Сохранение в localStorage для сравнения
  saveMetricToStorage(metric)
}

// Функция для получения единиц измерения
function getUnit(name) {
  switch (name) {
    case 'LCP':
    case 'FCP':
    case 'TTFB':
      return 'ms'
    case 'INP':
    case 'FID':
      return 'ms'
    case 'CLS':
      return ''
    default:
      return ''
  }
}

// Функция для сохранения метрик в localStorage
function saveMetricToStorage(metric) {
  try {
    const key = `web-vitals-${metric.name}`
    const existing = JSON.parse(localStorage.getItem(key) || '[]')
    
    // Сохраняем последние 10 измерений
    const updated = [metric, ...existing].slice(0, 10)
    localStorage.setItem(key, JSON.stringify(updated))
  } catch (error) {
    if (VITALS_CONFIG.debug) {
      console.warn('Failed to save metric to storage:', error)
    }
  }
}

// Функция для получения средних значений
function getAverageMetric(name) {
  try {
    const key = `web-vitals-${name}`
    const metrics = JSON.parse(localStorage.getItem(key) || '[]')
    
    if (metrics.length === 0) return null
    
    const sum = metrics.reduce((acc, metric) => acc + metric.value, 0)
    return sum / metrics.length
  } catch (error) {
    return null
  }
}

// Функция для сравнения метрик до и после оптимизации
function compareMetrics() {
  const metrics = ['LCP', 'INP', 'CLS', 'FCP', 'TTFB']
  const comparison = {}
  
  metrics.forEach(name => {
    const average = getAverageMetric(name)
    if (average) {
      const threshold = VITALS_CONFIG.thresholds[name]
      let status = 'unknown'
      
      if (threshold) {
        if (average <= threshold.good) {
          status = 'good'
        } else if (average <= threshold.needsImprovement) {
          status = 'needs-improvement'
        } else {
          status = 'poor'
        }
      }
      
      comparison[name] = {
        average: average.toFixed(2),
        unit: getUnit(name),
        status,
        threshold
      }
    }
  })
  
  return comparison
}

// Функция для генерации отчета
function generateReport() {
  const comparison = compareMetrics()
  const report = {
    timestamp: new Date().toISOString(),
    url: window.location.href,
    userAgent: navigator.userAgent,
    connection: navigator.connection ? {
      effectiveType: navigator.connection.effectiveType,
      downlink: navigator.connection.downlink,
      rtt: navigator.connection.rtt
    } : null,
    metrics: comparison,
    summary: {
      totalMetrics: Object.keys(comparison).length,
      goodMetrics: Object.values(comparison).filter(m => m.status === 'good').length,
      needsImprovementMetrics: Object.values(comparison).filter(m => m.status === 'needs-improvement').length,
      poorMetrics: Object.values(comparison).filter(m => m.status === 'poor').length
    }
  }
  
  return report
}

// Инициализация измерения Web Vitals
function initWebVitals() {
  // LCP - Largest Contentful Paint
  getLCP(logMetric, { reportAllChanges: true })
  
  // INP - Interaction to Next Paint (замена FID)
  getINP(logMetric, { reportAllChanges: true })
  
  // CLS - Cumulative Layout Shift
  getCLS(logMetric, { reportAllChanges: true })
  
  // FCP - First Contentful Paint
  getFCP(logMetric, { reportAllChanges: true })
  
  // TTFB - Time to First Byte
  getTTFB(logMetric, { reportAllChanges: true })
  
  // FID - First Input Delay (deprecated, но оставляем для совместимости)
  getFID(logMetric, { reportAllChanges: true })
  
  if (VITALS_CONFIG.debug) {
    console.log('[Web Vitals] Measurement initialized')
    
    // Экспорт функций для отладки
    window.webVitals = {
      compareMetrics,
      generateReport,
      getAverageMetric,
      logMetric
    }
  }
}

// Функция для измерения производительности компонентов
function measureComponentPerformance(componentName, renderFunction) {
  const startTime = performance.now()
  
  const result = renderFunction()
  
  const endTime = performance.now()
  const renderTime = endTime - startTime
  
  if (renderTime > 16) { // Больше одного кадра (60fps)
    console.warn(`[Performance] Slow render in ${componentName}: ${renderTime.toFixed(2)}ms`)
  }
  
  return result
}

// Функция для измерения времени загрузки ресурсов
function measureResourceLoading() {
  if (!window.performance || !window.performance.getEntriesByType) return
  
  const resources = window.performance.getEntriesByType('resource')
  const slowResources = resources.filter(resource => resource.duration > 1000)
  
  if (slowResources.length > 0) {
    console.warn('[Performance] Slow resources detected:', slowResources.map(r => ({
      name: r.name,
      duration: r.duration.toFixed(2) + 'ms',
      size: r.transferSize || 'unknown'
    })))
  }
}

// Функция для измерения времени загрузки страницы
function measurePageLoad() {
  if (!window.performance || !window.performance.timing) return
  
  const timing = window.performance.timing
  const navigation = window.performance.getEntriesByType('navigation')[0]
  
  const metrics = {
    domContentLoaded: timing.domContentLoadedEventEnd - timing.navigationStart,
    loadComplete: timing.loadEventEnd - timing.navigationStart,
    firstByte: timing.responseStart - timing.navigationStart,
    domInteractive: timing.domInteractive - timing.navigationStart
  }
  
  if (VITALS_CONFIG.debug) {
    console.log('[Performance] Page load metrics:', metrics)
  }
  
  return metrics
}

// Инициализация при загрузке страницы
if (typeof window !== 'undefined') {
  // Инициализация Web Vitals
  initWebVitals()
  
  // Измерение производительности ресурсов
  window.addEventListener('load', () => {
    measureResourceLoading()
    measurePageLoad()
  })
  
  // Экспорт функций для использования в компонентах
  window.performanceUtils = {
    measureComponentPerformance,
    compareMetrics,
    generateReport,
    getAverageMetric
  }
}

// Экспорт для использования в модулях
export {
  initWebVitals,
  measureComponentPerformance,
  compareMetrics,
  generateReport,
  getAverageMetric,
  VITALS_CONFIG
}