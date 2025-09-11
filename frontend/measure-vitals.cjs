const puppeteer = require('puppeteer');
const fs = require('fs');

async function measureCoreWebVitals() {
  const browser = await puppeteer.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  try {
    const page = await browser.newPage();
    
    // Настройка для измерения производительности
    await page.setViewport({ width: 1920, height: 1080 });
    await page.setCacheEnabled(false);
    
    // Включение метрик производительности
    await page.evaluateOnNewDocument(() => {
      // Переопределение PerformanceObserver для сбора метрик
      window.webVitals = {
        LCP: null,
        FID: null,
        CLS: null,
        INP: null,
        FCP: null,
        TTFB: null
      };

      // LCP
      new PerformanceObserver((list) => {
        const entries = list.getEntries();
        const lastEntry = entries[entries.length - 1];
        window.webVitals.LCP = lastEntry.startTime;
      }).observe({ entryTypes: ['largest-contentful-paint'] });

      // FCP
      new PerformanceObserver((list) => {
        const entries = list.getEntries();
        entries.forEach((entry) => {
          if (entry.name === 'first-contentful-paint') {
            window.webVitals.FCP = entry.startTime;
          }
        });
      }).observe({ entryTypes: ['paint'] });

      // CLS
      let clsValue = 0;
      new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          if (!entry.hadRecentInput) {
            clsValue += entry.value;
          }
        }
        window.webVitals.CLS = clsValue;
      }).observe({ entryTypes: ['layout-shift'] });

      // TTFB
      new PerformanceObserver((list) => {
        const entries = list.getEntries();
        entries.forEach((entry) => {
          if (entry.entryType === 'navigation') {
            window.webVitals.TTFB = entry.responseStart - entry.requestStart;
          }
        });
      }).observe({ entryTypes: ['navigation'] });

      // INP (Interaction to Next Paint) - симуляция
      let interactionStart = 0;
      document.addEventListener('click', () => {
        interactionStart = performance.now();
      });
      
      requestAnimationFrame(() => {
        if (interactionStart > 0) {
          window.webVitals.INP = performance.now() - interactionStart;
        }
      });
    });

    console.log('Загрузка страницы...');
    const startTime = Date.now();
    
    // Переход на страницу
    await page.goto('http://localhost:4173', {
      waitUntil: 'networkidle0',
      timeout: 30000
    });

    // Ожидание загрузки всех ресурсов
    await page.waitForTimeout(3000);

    // Сбор метрик
    const metrics = await page.evaluate(() => {
      const navigation = performance.getEntriesByType('navigation')[0];
      const paintEntries = performance.getEntriesByType('paint');
      
      return {
        LCP: window.webVitals.LCP || 0,
        FCP: window.webVitals.FCP || 0,
        CLS: window.webVitals.CLS || 0,
        INP: window.webVitals.INP || 0,
        TTFB: window.webVitals.TTFB || (navigation ? navigation.responseStart - navigation.requestStart : 0),
        loadTime: navigation ? navigation.loadEventEnd - navigation.fetchStart : 0,
        domContentLoaded: navigation ? navigation.domContentLoadedEventEnd - navigation.fetchStart : 0,
        firstByte: navigation ? navigation.responseStart - navigation.fetchStart : 0,
        // Дополнительные метрики
        totalResources: performance.getEntriesByType('resource').length,
        totalSize: performance.getEntriesByType('resource').reduce((total, entry) => {
          return total + (entry.transferSize || 0);
        }, 0),
        // Анализ чанков
        jsChunks: performance.getEntriesByType('resource')
          .filter(entry => entry.name.includes('.js'))
          .map(entry => ({
            name: entry.name.split('/').pop(),
            size: entry.transferSize || 0,
            loadTime: entry.responseEnd - entry.responseStart
          })),
        cssChunks: performance.getEntriesByType('resource')
          .filter(entry => entry.name.includes('.css'))
          .map(entry => ({
            name: entry.name.split('/').pop(),
            size: entry.transferSize || 0,
            loadTime: entry.responseEnd - entry.responseStart
          }))
      };
    });

    const loadTime = Date.now() - startTime;
    
    // Анализ производительности
    const analysis = {
      timestamp: new Date().toISOString(),
      url: 'http://localhost:4173',
      loadTime: loadTime,
      coreWebVitals: {
        LCP: {
          value: metrics.LCP,
          status: metrics.LCP <= 2500 ? 'good' : metrics.LCP <= 4000 ? 'needs-improvement' : 'poor',
          target: 2500
        },
        INP: {
          value: metrics.INP,
          status: metrics.INP <= 200 ? 'good' : metrics.INP <= 500 ? 'needs-improvement' : 'poor',
          target: 200
        },
        CLS: {
          value: metrics.CLS,
          status: metrics.CLS <= 0.1 ? 'good' : metrics.CLS <= 0.25 ? 'needs-improvement' : 'poor',
          target: 0.1
        },
        FCP: {
          value: metrics.FCP,
          status: metrics.FCP <= 1800 ? 'good' : metrics.FCP <= 3000 ? 'needs-improvement' : 'poor',
          target: 1800
        },
        TTFB: {
          value: metrics.TTFB,
          status: metrics.TTFB <= 800 ? 'good' : metrics.TTFB <= 1800 ? 'needs-improvement' : 'poor',
          target: 800
        }
      },
      performance: {
        totalResources: metrics.totalResources,
        totalSize: metrics.totalSize,
        jsChunks: metrics.jsChunks,
        cssChunks: metrics.cssChunks
      }
    };

    // Сохранение результатов
    fs.writeFileSync('vitals-before.json', JSON.stringify(analysis, null, 2));
    
    console.log('\n=== CORE WEB VITALS - ДО ОПТИМИЗАЦИИ ===');
    console.log(`LCP: ${metrics.LCP.toFixed(2)}ms (${analysis.coreWebVitals.LCP.status})`);
    console.log(`INP: ${metrics.INP.toFixed(2)}ms (${analysis.coreWebVitals.INP.status})`);
    console.log(`CLS: ${metrics.CLS.toFixed(4)} (${analysis.coreWebVitals.CLS.status})`);
    console.log(`FCP: ${metrics.FCP.toFixed(2)}ms (${analysis.coreWebVitals.FCP.status})`);
    console.log(`TTFB: ${metrics.TTFB.toFixed(2)}ms (${analysis.coreWebVitals.TTFB.status})`);
    console.log(`\nОбщее время загрузки: ${loadTime}ms`);
    console.log(`Общий размер ресурсов: ${(metrics.totalSize / 1024).toFixed(2)} KB`);
    console.log(`Количество ресурсов: ${metrics.totalResources}`);

    return analysis;

  } finally {
    await browser.close();
  }
}

// Запуск измерения
measureCoreWebVitals().catch(console.error);