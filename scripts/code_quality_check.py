#!/usr/bin/env python3
"""
Скрипт проверки качества кода
Выполняет комплексную проверку кода на предмет качества, безопасности и производительности
"""

import os
import sys
import subprocess
import json
import ast
import re
from pathlib import Path
from typing import List, Dict, Any, Tuple
import logging

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CodeQualityChecker:
    """Проверка качества кода"""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.issues = []
        self.stats = {
            'files_checked': 0,
            'issues_found': 0,
            'security_issues': 0,
            'performance_issues': 0,
            'style_issues': 0
        }
    
    def check_python_files(self) -> List[Dict[str, Any]]:
        """Проверка Python файлов"""
        python_files = list(self.project_root.rglob("*.py"))
        issues = []
        
        for file_path in python_files:
            if self._should_skip_file(file_path):
                continue
            
            self.stats['files_checked'] += 1
            file_issues = self._check_python_file(file_path)
            issues.extend(file_issues)
        
        return issues
    
    def _should_skip_file(self, file_path: Path) -> bool:
        """Проверить, нужно ли пропустить файл"""
        skip_patterns = [
            '__pycache__',
            '.git',
            'venv',
            'env',
            'node_modules',
            '.pytest_cache',
            'migrations/versions'
        ]
        
        return any(pattern in str(file_path) for pattern in skip_patterns)
    
    def _check_python_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Проверка одного Python файла"""
        issues = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Проверка синтаксиса
            try:
                ast.parse(content)
            except SyntaxError as e:
                issues.append({
                    'file': str(file_path),
                    'line': e.lineno,
                    'type': 'syntax_error',
                    'severity': 'error',
                    'message': f"Syntax error: {e.msg}"
                })
                return issues
            
            # Проверка на неиспользуемые импорты
            issues.extend(self._check_unused_imports(file_path, content))
            
            # Проверка на потенциальные проблемы безопасности
            issues.extend(self._check_security_issues(file_path, content))
            
            # Проверка на проблемы производительности
            issues.extend(self._check_performance_issues(file_path, content))
            
            # Проверка стиля кода
            issues.extend(self._check_style_issues(file_path, content))
            
            # Проверка на TODO/FIXME
            issues.extend(self._check_todos(file_path, content))
            
        except Exception as e:
            logger.error(f"File check error in {file_path}: {e}")
        
        return issues
    
    def _check_unused_imports(self, file_path: Path, content: str) -> List[Dict[str, Any]]:
        """Проверка на неиспользуемые импорты"""
        issues = []
        
        try:
            tree = ast.parse(content)
            imports = []
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.append(node.module)
                    for alias in node.names:
                        imports.append(alias.name)
            
            # Простая проверка использования импортов
            for import_name in imports:
                if import_name not in content.replace(f"import {import_name}", ""):
                    issues.append({
                        'file': str(file_path),
                        'line': 0,
                        'type': 'unused_import',
                        'severity': 'warning',
                        'message': f"Unused import: {import_name}"
                    })
        
        except Exception as e:
            logger.debug(f"Unused imports check error in {file_path}: {e}")
        
        return issues
    
    def _check_security_issues(self, file_path: Path, content: str) -> List[Dict[str, Any]]:
        """Проверка на проблемы безопасности"""
        issues = []
        
        # Проверка на использование eval/exec (только реальные вызовы)
        if re.search(r'\beval\s*\([^)]', content) and not re.search(r'["\']eval\(["\']', content):
            issues.append({
                'file': str(file_path),
                'line': 0,
                'type': 'security_issue',
                'severity': 'error',
                'message': "Use of eval() detected - potential security risk"
            })
            self.stats['security_issues'] += 1
        
        if re.search(r'\bexec\s*\([^)]', content) and not re.search(r'["\']exec\(["\']', content):
            issues.append({
                'file': str(file_path),
                'line': 0,
                'type': 'security_issue',
                'severity': 'error',
                'message': "Use of exec() detected - potential security risk"
            })
            self.stats['security_issues'] += 1
        
        # Проверка на хардкод паролей/ключей
        if re.search(r'password\s*=\s*["\'][^"\']+["\']', content, re.IGNORECASE):
            issues.append({
                'file': str(file_path),
                'line': 0,
                'type': 'security_issue',
                'severity': 'warning',
                'message': "Hardcoded password detected"
            })
            self.stats['security_issues'] += 1
        
        # Проверка на SQL инъекции
        if re.search(r'f["\'].*\{.*\}.*SELECT', content, re.IGNORECASE):
            issues.append({
                'file': str(file_path),
                'line': 0,
                'type': 'security_issue',
                'severity': 'warning',
                'message': "Potential SQL injection in f-string"
            })
            self.stats['security_issues'] += 1
        
        return issues
    
    def _check_performance_issues(self, file_path: Path, content: str) -> List[Dict[str, Any]]:
        """Проверка на проблемы производительности"""
        issues = []
        
        # Проверка на использование sleep в циклах
        if re.search(r'for.*:\s*.*sleep\s*\(', content, re.MULTILINE):
            issues.append({
                'file': str(file_path),
                'line': 0,
                'type': 'performance_issue',
                'severity': 'warning',
                'message': "sleep() in loop detected - consider using asyncio.sleep()"
            })
            self.stats['performance_issues'] += 1
        
        # Проверка на неэффективные операции со строками
        if re.search(r'for.*:\s*.*\+=.*["\']', content, re.MULTILINE):
            issues.append({
                'file': str(file_path),
                'line': 0,
                'type': 'performance_issue',
                'severity': 'info',
                'message': "String concatenation in loop - consider using join()"
            })
            self.stats['performance_issues'] += 1
        
        return issues
    
    def _check_style_issues(self, file_path: Path, content: str) -> List[Dict[str, Any]]:
        """Проверка стиля кода"""
        issues = []
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Проверка длины строки
            if len(line) > 120:
                issues.append({
                    'file': str(file_path),
                    'line': i,
                    'type': 'style_issue',
                    'severity': 'info',
                    'message': f"Line too long ({len(line)} characters)"
                })
                self.stats['style_issues'] += 1
            
            # Проверка на trailing whitespace
            if line.rstrip() != line and line.strip():
                issues.append({
                    'file': str(file_path),
                    'line': i,
                    'type': 'style_issue',
                    'severity': 'info',
                    'message': "Trailing whitespace"
                })
                self.stats['style_issues'] += 1
        
        return issues
    
    def _check_todos(self, file_path: Path, content: str) -> List[Dict[str, Any]]:
        """Проверка на TODO/FIXME"""
        issues = []
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            if re.search(r'\b(TODO|FIXME|XXX|HACK|BUG)\b', line, re.IGNORECASE):
                issues.append({
                    'file': str(file_path),
                    'line': i,
                    'type': 'todo',
                    'severity': 'info',
                    'message': f"TODO/FIXME found: {line.strip()}"
                })
        
        return issues
    
    def check_typescript_files(self) -> List[Dict[str, Any]]:
        """Проверка TypeScript файлов"""
        ts_files = list(self.project_root.rglob("*.ts"))
        tsx_files = list(self.project_root.rglob("*.tsx"))
        all_files = ts_files + tsx_files
        
        issues = []
        
        for file_path in all_files:
            if self._should_skip_file(file_path):
                continue
            
            self.stats['files_checked'] += 1
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Проверка на console.log
                lines = content.split('\n')
                for i, line in enumerate(lines, 1):
                    if 'console.log' in line:
                        issues.append({
                            'file': str(file_path),
                            'line': i,
                            'type': 'style_issue',
                            'severity': 'warning',
                            'message': "console.log found - consider using logger"
                        })
                        self.stats['style_issues'] += 1
                
                # Проверка на неиспользуемые переменные
                if 'const ' in content or 'let ' in content:
                    # Простая проверка на неиспользуемые переменные
                    pass
                
            except Exception as e:
                logger.error(f"TypeScript file check error in {file_path}: {e}")
        
        return issues
    
    def run_quality_check(self) -> Dict[str, Any]:
        """Запустить полную проверку качества кода"""
        logger.info("Starting code quality check")
        
        all_issues = []
        
        # Проверка Python файлов
        python_issues = self.check_python_files()
        all_issues.extend(python_issues)
        
        # Проверка TypeScript файлов
        typescript_issues = self.check_typescript_files()
        all_issues.extend(typescript_issues)
        
        # Подсчет статистики
        self.stats['issues_found'] = len(all_issues)
        
        # Группировка по типам
        issues_by_type = {}
        for issue in all_issues:
            issue_type = issue['type']
            if issue_type not in issues_by_type:
                issues_by_type[issue_type] = []
            issues_by_type[issue_type].append(issue)
        
        # Группировка по серьезности
        issues_by_severity = {}
        for issue in all_issues:
            severity = issue['severity']
            if severity not in issues_by_severity:
                issues_by_severity[severity] = []
            issues_by_severity[severity].append(issue)
        
        result = {
            'stats': self.stats,
            'issues_by_type': issues_by_type,
            'issues_by_severity': issues_by_severity,
            'all_issues': all_issues
        }
        
        logger.info(f"Code quality check completed: {self.stats['files_checked']} files, {self.stats['issues_found']} issues")
        
        return result
    
    def print_report(self, result: Dict[str, Any]):
        """Вывести отчет о проверке"""
        print("\n" + "="*60)
        print("CODE QUALITY REPORT")
        print("="*60)
        
        stats = result['stats']
        print(f"\nFiles checked: {stats['files_checked']}")
        print(f"Total issues: {stats['issues_found']}")
        print(f"Security issues: {stats['security_issues']}")
        print(f"Performance issues: {stats['performance_issues']}")
        print(f"Style issues: {stats['style_issues']}")
        
        # Вывод по серьезности
        for severity in ['error', 'warning', 'info']:
            issues = result['issues_by_severity'].get(severity, [])
            if issues:
                print(f"\n{severity.upper()} ISSUES ({len(issues)}):")
                for issue in issues[:10]:  # Показываем первые 10
                    print(f"  {issue['file']}:{issue['line']} - {issue['message']}")
                if len(issues) > 10:
                    print(f"  ... and {len(issues) - 10} more")
        
        print("\n" + "="*60)

def main():
    """Главная функция"""
    project_root = os.getcwd()
    checker = CodeQualityChecker(project_root)
    
    result = checker.run_quality_check()
    checker.print_report(result)
    
    # Сохраняем результат в файл
    with open('code_quality_report.json', 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    
    print(f"\nDetailed report saved to: code_quality_report.json")
    
    # Возвращаем код выхода на основе найденных проблем
    if result['stats']['security_issues'] > 0:
        sys.exit(1)
    elif result['stats']['issues_found'] > 50:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()