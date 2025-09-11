const fs = require('fs');
const path = require('path');

// Анализ собранных файлов для оценки производительности
function analyzeBuildPerformance() {
  const distPath = path.join(__dirname, 'dist');
  
  if (!fs.existsSync(distPath)) {
    console.log('Папка dist не найдена. Сначала выполните npm run build');
    return;
  }

  // Анализ HTML файла
  const htmlPath = path.join(distPath, 'index.html');
  const htmlContent = fs.readFileSync(htmlPath, 'utf8');
  
  // Анализ CSS файлов
  const assetsPath = path.join(distPath, 'assets');
  const cssFiles = fs.readdirSync(assetsPath).filter(file => file.endsWith('.css'));
  let totalCssSize = 0;
  let cssFilesInfo = [];
  
  cssFiles.forEach(file => {
    const filePath = path.join(assetsPath, file);
    const stats = fs.statSync(filePath);
    const size = stats.size;
    totalCssSize += size;
    cssFilesInfo.push({
      name: file,
      size: size,
      gzipSize: Math.round(size * 0.3) // Примерная оценка gzip
    });
  });

  // Анализ JS файлов
  const jsFiles = fs.readdirSync(assetsPath).filter(file => file.endsWith('.js'));
  let totalJsSize = 0;
  let jsFilesInfo = [];
  
  jsFiles.forEach(file => {
    const filePath = path.join(assetsPath, file);
    const stats = fs.statSync(filePath);
    const size = stats.size;
    totalJsSize += size;
    jsFilesInfo.push({
      name: file,
      size: size,
      gzipSize: Math.round(size * 0.3) // Примерная оценка gzip
    });
  });

  // Анализ критического CSS
  const criticalCssInHtml = htmlContent.includes('<style>') ? 
    htmlContent.match(/<style>([\s\S]*?)<\/style>/)[1].length : 0;

  // Анализ preload/preconnect
  const preloadCount = (htmlContent.match(/rel="preload"/g) || []).length;
  const preconnectCount = (htmlContent.match(/rel="preconnect"/g) || []).length;
  const dnsPrefetchCount = (htmlContent.match(/rel="dns-prefetch"/g) || []).length;

  // Анализ чанков
  const vendorChunks = jsFilesInfo.filter(file => file.name.includes('vendor'));
  const appChunks = jsFilesInfo.filter(file => !file.name.includes('vendor'));

  // Оценка производительности на основе анализа
  const analysis = {
    timestamp: new Date().toISOString(),
    buildAnalysis: {
      totalFiles: cssFiles.length + jsFiles.length,
      totalSize: totalCssSize + totalJsSize,
      totalGzipSize: Math.round((totalCssSize + totalJsSize) * 0.3),
      css: {
        files: cssFilesInfo,
        totalSize: totalCssSize,
        totalGzipSize: Math.round(totalCssSize * 0.3),
        largestFile: cssFilesInfo.reduce((max, file) => file.size > max.size ? file : max, {size: 0})
      },
      js: {
        files: jsFilesInfo,
        totalSize: totalJsSize,
        totalGzipSize: Math.round(totalJsSize * 0.3),
        vendorChunks: vendorChunks,
        appChunks: appChunks,
        largestFile: jsFilesInfo.reduce((max, file) => file.size > max.size ? file : max, {size: 0})
      }
    },
    optimizations: {
      criticalCss: {
        inline: criticalCssInHtml > 0,
        size: criticalCssInHtml
      },
      resourceHints: {
        preload: preloadCount,
        preconnect: preconnectCount,
        dnsPrefetch: dnsPrefetchCount
      },
      codeSplitting: {
        vendorChunks: vendorChunks.length,
        appChunks: appChunks.length,
        totalChunks: jsFilesInfo.length
      }
    },
    performanceEstimates: {
      // Оценки на основе размера файлов и оптимизаций
      estimatedLCP: calculateEstimatedLCP(totalCssSize, totalJsSize, criticalCssInHtml > 0),
      estimatedFCP: calculateEstimatedFCP(totalCssSize, criticalCssInHtml > 0),
      estimatedCLS: calculateEstimatedCLS(criticalCssInHtml > 0),
      estimatedINP: calculateEstimatedINP(totalJsSize, vendorChunks.length),
      estimatedTTFB: 100 // Локальный сервер
    }
  };

  // Сохранение результатов
  fs.writeFileSync('performance-analysis-before.json', JSON.stringify(analysis, null, 2));
  
  console.log('\n=== АНАЛИЗ ПРОИЗВОДИТЕЛЬНОСТИ - ДО ОПТИМИЗАЦИИ ===');
  console.log(`Общий размер: ${(analysis.buildAnalysis.totalSize / 1024).toFixed(2)} KB`);
  console.log(`Общий размер (gzip): ${(analysis.buildAnalysis.totalGzipSize / 1024).toFixed(2)} KB`);
  console.log(`Количество файлов: ${analysis.buildAnalysis.totalFiles}`);
  console.log(`\nCSS файлы: ${cssFilesInfo.length}`);
  cssFilesInfo.forEach(file => {
    console.log(`  - ${file.name}: ${(file.size / 1024).toFixed(2)} KB (${(file.gzipSize / 1024).toFixed(2)} KB gzip)`);
  });
  console.log(`\nJS файлы: ${jsFilesInfo.length}`);
  jsFilesInfo.forEach(file => {
    console.log(`  - ${file.name}: ${(file.size / 1024).toFixed(2)} KB (${(file.gzipSize / 1024).toFixed(2)} KB gzip)`);
  });
  
  console.log(`\n=== ОПТИМИЗАЦИИ ===`);
  console.log(`Критический CSS: ${analysis.optimizations.criticalCss.inline ? 'Да' : 'Нет'} (${analysis.optimizations.criticalCss.size} символов)`);
  console.log(`Preload: ${preloadCount}, Preconnect: ${preconnectCount}, DNS Prefetch: ${dnsPrefetchCount}`);
  console.log(`Code Splitting: ${vendorChunks.length} vendor чанков, ${appChunks.length} app чанков`);
  
  console.log(`\n=== ОЦЕНКА CORE WEB VITALS ===`);
  console.log(`LCP: ~${analysis.performanceEstimates.estimatedLCP}ms`);
  console.log(`FCP: ~${analysis.performanceEstimates.estimatedFCP}ms`);
  console.log(`CLS: ~${analysis.performanceEstimates.estimatedCLS}`);
  console.log(`INP: ~${analysis.performanceEstimates.estimatedINP}ms`);
  console.log(`TTFB: ~${analysis.performanceEstimates.estimatedTTFB}ms`);

  return analysis;
}

function calculateEstimatedLCP(cssSize, jsSize, hasCriticalCss) {
  // Базовая оценка LCP на основе размера ресурсов
  let baseTime = 1000; // 1 секунда базовая загрузка
  
  // Влияние CSS
  if (hasCriticalCss) {
    baseTime += cssSize / 10000; // Критический CSS ускоряет
  } else {
    baseTime += cssSize / 5000; // Обычный CSS медленнее
  }
  
  // Влияние JS
  baseTime += jsSize / 15000;
  
  return Math.round(baseTime);
}

function calculateEstimatedFCP(cssSize, hasCriticalCss) {
  // FCP в основном зависит от CSS
  let baseTime = 800;
  
  if (hasCriticalCss) {
    baseTime += cssSize / 20000;
  } else {
    baseTime += cssSize / 8000;
  }
  
  return Math.round(baseTime);
}

function calculateEstimatedCLS(hasCriticalCss) {
  // CLS зависит от наличия критического CSS
  if (hasCriticalCss) {
    return 0.05; // Хороший CLS с критическим CSS
  } else {
    return 0.15; // Плохой CLS без критического CSS
  }
}

function calculateEstimatedINP(jsSize, vendorChunks) {
  // INP зависит от размера JS и количества чанков
  let baseTime = 150;
  
  baseTime += jsSize / 20000;
  
  // Больше чанков = лучше для INP
  if (vendorChunks > 3) {
    baseTime -= 50;
  }
  
  return Math.max(50, Math.round(baseTime));
}

// Запуск анализа
analyzeBuildPerformance();