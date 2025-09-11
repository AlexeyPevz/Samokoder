#!/usr/bin/env python3
"""
Исправленный анализатор реального покрытия тестами
Учитывает все тесты, включая тесты в классах
"""

import os
import re
import json
from pathlib import Path
from typing import Dict, List, Set, Tuple
from datetime import datetime

class RealCoverageAnalyzerFixed:
    """Исправленный анализатор реального покрытия тестами"""
    
    def __init__(self, workspace_path: str = "/workspace"):
        self.workspace_path = Path(workspace_path)
        self.backend_path = self.workspace_path / "backend"
        self.tests_path = self.workspace_path / "tests"
        
        self.backend_files = []
        self.test_files = []
        self.functions = {}
        self.tests = {}
        self.coverage = {}
        
    def analyze_backend_files(self):
        """Анализ файлов backend"""
        print("🔍 Анализ файлов backend...")
        
        for py_file in self.backend_path.rglob("*.py"):
            if py_file.name == "__init__.py":
                continue
                
            self.backend_files.append(py_file)
            
            # Анализ функций в файле
            functions = self._extract_functions(py_file)
            self.functions[str(py_file.relative_to(self.workspace_path))] = functions
            
        print(f"   Найдено {len(self.backend_files)} файлов Python")
        print(f"   Найдено {sum(len(f) for f in self.functions.values())} функций")
    
    def analyze_test_files(self):
        """Анализ файлов тестов"""
        print("🧪 Анализ файлов тестов...")
        
        for py_file in self.tests_path.rglob("*.py"):
            if py_file.name == "__init__.py":
                continue
                
            self.test_files.append(py_file)
            
            # Анализ тестов в файле
            tests = self._extract_tests(py_file)
            self.tests[str(py_file.relative_to(self.workspace_path))] = tests
            
        print(f"   Найдено {len(self.test_files)} файлов тестов")
        print(f"   Найдено {sum(len(t) for t in self.tests.values())} тестов")
    
    def _extract_functions(self, file_path: Path) -> List[Dict]:
        """Извлечение функций из файла"""
        functions = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Поиск функций
            function_pattern = r'^(async\s+)?def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
            matches = re.finditer(function_pattern, content, re.MULTILINE)
            
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                function_name = match.group(2)
                is_async = match.group(1) is not None
                
                functions.append({
                    'name': function_name,
                    'line': line_num,
                    'async': is_async,
                    'file': str(file_path.relative_to(self.workspace_path))
                })
                
        except Exception as e:
            print(f"   Ошибка при анализе {file_path}: {e}")
            
        return functions
    
    def _extract_tests(self, file_path: Path) -> List[Dict]:
        """Извлечение тестов из файла (исправленная версия)"""
        tests = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Поиск тестов (включая тесты в классах)
            test_pattern = r'^\s*(async\s+)?def\s+(test_[a-zA-Z0-9_]*)\s*\('
            matches = re.finditer(test_pattern, content, re.MULTILINE)
            
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                test_name = match.group(2)
                is_async = match.group(1) is not None
                
                tests.append({
                    'name': test_name,
                    'line': line_num,
                    'async': is_async,
                    'file': str(file_path.relative_to(self.workspace_path))
                })
                
        except Exception as e:
            print(f"   Ошибка при анализе {file_path}: {e}")
            
        return tests
    
    def analyze_coverage(self):
        """Анализ покрытия тестами"""
        print("📊 Анализ покрытия тестами...")
        
        # Анализ покрытия по файлам
        for file_path, functions in self.functions.items():
            file_coverage = self._analyze_file_coverage(file_path, functions)
            self.coverage[file_path] = file_coverage
            
        # Общая статистика
        total_functions = sum(len(f) for f in self.functions.values())
        covered_functions = sum(c['covered_functions'] for c in self.coverage.values())
        
        print(f"   Общее покрытие: {covered_functions}/{total_functions} ({covered_functions/total_functions*100:.1f}%)")
    
    def _analyze_file_coverage(self, file_path: str, functions: List[Dict]) -> Dict:
        """Анализ покрытия конкретного файла"""
        covered_functions = 0
        uncovered_functions = []
        
        # Более детальный анализ
        for func in functions:
            if self._function_is_covered(func):
                covered_functions += 1
            else:
                uncovered_functions.append(func)
        
        return {
            'total_functions': len(functions),
            'covered_functions': covered_functions,
            'uncovered_functions': uncovered_functions,
            'coverage_percent': covered_functions / len(functions) * 100 if functions else 0
        }
    
    def _function_is_covered(self, function: Dict) -> bool:
        """Проверка, покрыта ли функция тестами"""
        func_name = function['name']
        
        # Поиск упоминаний функции в тестах
        for test_file, tests in self.tests.items():
            test_file_path = self.workspace_path / test_file
            
            try:
                with open(test_file_path, 'r', encoding='utf-8') as f:
                    test_content = f.read()
                    
                if func_name in test_content:
                    return True
                    
            except Exception:
                continue
                
        return False
    
    def analyze_critical_files(self):
        """Анализ критических файлов"""
        print("🚨 Анализ критических файлов...")
        
        critical_files = [
            "backend/api/api_keys.py",
            "backend/api/mfa.py", 
            "backend/auth/dependencies.py",
            "backend/main.py",
            "backend/services/encryption_service.py",
            "backend/services/connection_manager.py",
            "backend/services/supabase_manager.py"
        ]
        
        critical_analysis = {}
        
        for file_path in critical_files:
            if file_path in self.functions:
                functions = self.functions[file_path]
                coverage = self.coverage.get(file_path, {})
                
                critical_analysis[file_path] = {
                    'functions': functions,
                    'coverage': coverage,
                    'critical_functions': self._identify_critical_functions(functions),
                    'uncovered_critical': self._find_uncovered_critical(functions, coverage)
                }
                
        return critical_analysis
    
    def _identify_critical_functions(self, functions: List[Dict]) -> List[Dict]:
        """Идентификация критических функций"""
        critical_keywords = [
            'auth', 'jwt', 'token', 'password', 'encrypt', 'decrypt',
            'mfa', 'totp', 'api_key', 'connection', 'database', 'redis',
            'validate', 'verify', 'hash', 'secret', 'key'
        ]
        
        critical_functions = []
        
        for func in functions:
            func_name_lower = func['name'].lower()
            if any(keyword in func_name_lower for keyword in critical_keywords):
                critical_functions.append(func)
                
        return critical_functions
    
    def _find_uncovered_critical(self, functions: List[Dict], coverage: Dict) -> List[Dict]:
        """Поиск непокрытых критических функций"""
        uncovered_critical = []
        
        for func in functions:
            if not self._function_is_covered(func):
                func_name_lower = func['name'].lower()
                critical_keywords = [
                    'auth', 'jwt', 'token', 'password', 'encrypt', 'decrypt',
                    'mfa', 'totp', 'api_key', 'connection', 'database', 'redis',
                    'validate', 'verify', 'hash', 'secret', 'key'
                ]
                
                if any(keyword in func_name_lower for keyword in critical_keywords):
                    uncovered_critical.append(func)
                    
        return uncovered_critical
    
    def generate_report(self):
        """Генерация отчета"""
        print("📋 Генерация отчета...")
        
        # Общая статистика
        total_files = len(self.backend_files)
        total_functions = sum(len(f) for f in self.functions.values())
        total_tests = sum(len(t) for t in self.tests.values())
        
        covered_functions = sum(c['covered_functions'] for c in self.coverage.values())
        overall_coverage = covered_functions / total_functions * 100 if total_functions > 0 else 0
        
        # Анализ критических файлов
        critical_analysis = self.analyze_critical_files()
        
        # Создание отчета
        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_backend_files': total_files,
                'total_functions': total_functions,
                'total_tests': total_tests,
                'covered_functions': covered_functions,
                'overall_coverage_percent': overall_coverage
            },
            'critical_files': critical_analysis,
            'detailed_coverage': self.coverage
        }
        
        # Сохранение отчета
        report_file = self.workspace_path / f"real_coverage_report_fixed_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"   Отчет сохранен: {report_file}")
        
        # Вывод критических пробелов
        self._print_critical_gaps(critical_analysis)
        
        return report
    
    def _print_critical_gaps(self, critical_analysis: Dict):
        """Вывод критических пробелов"""
        print("\n🚨 КРИТИЧЕСКИЕ ПРОБЕЛЫ В ПОКРЫТИИ:")
        print("=" * 60)
        
        for file_path, analysis in critical_analysis.items():
            uncovered_critical = analysis['uncovered_critical']
            
            if uncovered_critical:
                print(f"\n📁 {file_path}:")
                print(f"   Покрытие: {analysis['coverage'].get('coverage_percent', 0):.1f}%")
                print(f"   Непокрытые критические функции:")
                
                for func in uncovered_critical:
                    print(f"     ❌ {func['name']} (строка {func['line']})")
            else:
                print(f"\n✅ {file_path}: Все критические функции покрыты")
    
    def run_analysis(self):
        """Запуск полного анализа"""
        print("🚀 ЗАПУСК ИСПРАВЛЕННОГО АНАЛИЗА РЕАЛЬНОГО ПОКРЫТИЯ")
        print("=" * 60)
        
        self.analyze_backend_files()
        self.analyze_test_files()
        self.analyze_coverage()
        
        report = self.generate_report()
        
        print("\n" + "=" * 60)
        print("📊 АНАЛИЗ ЗАВЕРШЕН")
        print("=" * 60)
        
        return report

def main():
    """Основная функция"""
    analyzer = RealCoverageAnalyzerFixed()
    report = analyzer.run_analysis()
    
    # Вывод итоговой статистики
    summary = report['summary']
    print(f"\n📈 ИТОГОВАЯ СТАТИСТИКА:")
    print(f"   Файлов backend: {summary['total_backend_files']}")
    print(f"   Функций: {summary['total_functions']}")
    print(f"   Тестов: {summary['total_tests']}")
    print(f"   Покрытых функций: {summary['covered_functions']}")
    print(f"   Общее покрытие: {summary['overall_coverage_percent']:.1f}%")
    
    if summary['overall_coverage_percent'] < 80:
        print(f"\n⚠️  ВНИМАНИЕ: Покрытие ниже 80%!")
        print(f"   Рекомендуется увеличить покрытие до 80%+")
    else:
        print(f"\n🎉 ОТЛИЧНО: Покрытие выше 80%!")
    
    return 0 if summary['overall_coverage_percent'] >= 80 else 1

if __name__ == "__main__":
    exit(main())