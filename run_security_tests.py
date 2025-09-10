#!/usr/bin/env python3
"""
Запуск всех тестов безопасности
Инженер по безопасности с 20-летним опытом
"""

import os
import sys
import subprocess
import logging
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_tests.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class SecurityTestRunner:
    """Запуск тестов безопасности"""
    
    def __init__(self):
        self.workspace_root = Path(__file__).parent
        self.tests_dir = self.workspace_root / "tests"
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "total_tests": 0,
            "passed_tests": 0,
            "failed_tests": 0,
            "test_categories": {},
            "security_coverage": 0.0,
            "critical_tests_passed": 0,
            "critical_tests_failed": 0
        }
    
    def run_test_category(self, category: str, test_files: List[str]) -> Dict[str, Any]:
        """Запуск тестов определенной категории"""
        logger.info(f"Running {category} tests...")
        
        category_results = {
            "category": category,
            "total_tests": 0,
            "passed_tests": 0,
            "failed_tests": 0,
            "test_files": [],
            "coverage": 0.0
        }
        
        for test_file in test_files:
            test_path = self.tests_dir / test_file
            if test_path.exists():
                try:
                    logger.info(f"Running {test_file}...")
                    
                    # Запускаем тест с детальным выводом
                    result = subprocess.run([
                        sys.executable, "-m", "pytest", 
                        str(test_path), "-v", "--tb=short", 
                        "--cov=security_patches", "--cov-report=term-missing"
                    ], cwd=self.workspace_root, capture_output=True, text=True)
                    
                    # Парсим результаты
                    lines = result.stdout.split('\n')
                    test_count = 0
                    passed_count = 0
                    failed_count = 0
                    
                    for line in lines:
                        if "::" in line and ("PASSED" in line or "FAILED" in line):
                            test_count += 1
                            if "PASSED" in line:
                                passed_count += 1
                            elif "FAILED" in line:
                                failed_count += 1
                    
                    category_results["test_files"].append({
                        "file": test_file,
                        "total": test_count,
                        "passed": passed_count,
                        "failed": failed_count,
                        "status": "PASSED" if failed_count == 0 else "FAILED"
                    })
                    
                    category_results["total_tests"] += test_count
                    category_results["passed_tests"] += passed_count
                    category_results["failed_tests"] += failed_count
                    
                    if test_count > 0:
                        category_results["coverage"] = (passed_count / test_count) * 100
                    
                    logger.info(f"{test_file}: {passed_count}/{test_count} tests passed")
                    
                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed to run {test_file}: {e}")
                    category_results["test_files"].append({
                        "file": test_file,
                        "total": 0,
                        "passed": 0,
                        "failed": 0,
                        "status": "ERROR",
                        "error": str(e)
                    })
            else:
                logger.warning(f"Test file not found: {test_file}")
        
        return category_results
    
    def run_all_security_tests(self) -> Dict[str, Any]:
        """Запуск всех тестов безопасности"""
        logger.info("Starting comprehensive security testing...")
        
        # Определяем категории тестов
        test_categories = {
            "Authentication (V2)": [
                "test_security_asvs_v2_auth.py",
                "test_security_critical_fixes.py::TestAuthenticationSecurity"
            ],
            "Session Management (V3)": [
                "test_security_asvs_v3_sessions.py",
                "test_security_critical_fixes.py::TestSessionSecurity"
            ],
            "Access Control (V4)": [
                "test_security_asvs_v4_access_control.py",
                "test_security_critical_fixes.py::TestAccessControl"
            ],
            "Input Validation (V5)": [
                "test_security_asvs_v5_validation.py",
                "test_security_critical_fixes.py::TestInputValidation"
            ],
            "Error Handling (V7)": [
                "test_security_asvs_v7_errors_logging.py",
                "test_security_critical_fixes.py::TestErrorHandling"
            ],
            "Configuration (V10)": [
                "test_security_asvs_v10_configuration.py",
                "test_security_critical_fixes.py::TestSecretsManagement"
            ],
            "API Security (V12)": [
                "test_security_asvs_v12_api_security.py",
                "test_security_critical_fixes.py::TestAPISecurity"
            ],
            "Integration Tests": [
                "test_security_critical_fixes.py::TestIntegrationFixes"
            ],
            "Performance Tests": [
                "test_security_critical_fixes.py::TestPerformanceSecurity"
            ]
        }
        
        # Запускаем тесты по категориям
        for category, test_files in test_categories.items():
            category_results = self.run_test_category(category, test_files)
            self.results["test_categories"][category] = category_results
            
            # Обновляем общую статистику
            self.results["total_tests"] += category_results["total_tests"]
            self.results["passed_tests"] += category_results["passed_tests"]
            self.results["failed_tests"] += category_results["failed_tests"]
            
            # Считаем критические тесты
            if category in ["Authentication (V2)", "Session Management (V3)", 
                          "Access Control (V4)", "Input Validation (V5)"]:
                self.results["critical_tests_passed"] += category_results["passed_tests"]
                self.results["critical_tests_failed"] += category_results["failed_tests"]
        
        # Вычисляем общее покрытие
        if self.results["total_tests"] > 0:
            self.results["security_coverage"] = (self.results["passed_tests"] / self.results["total_tests"]) * 100
        
        return self.results
    
    def generate_test_report(self) -> str:
        """Генерация отчета по тестам"""
        report = f"""
# 🧪 Security Tests Report

**Generated**: {self.results['timestamp']}

## 📊 Summary

- **Total Tests**: {self.results['total_tests']}
- **Passed**: {self.results['passed_tests']} ✅
- **Failed**: {self.results['failed_tests']} ❌
- **Coverage**: {self.results['security_coverage']:.1f}%
- **Critical Tests**: {self.results['critical_tests_passed']}/{self.results['critical_tests_passed'] + self.results['critical_tests_failed']}

## 📋 Test Categories

"""
        
        for category, results in self.results["test_categories"].items():
            status_icon = "✅" if results["failed_tests"] == 0 else "❌"
            report += f"### {status_icon} {category}\n"
            report += f"- **Tests**: {results['passed_tests']}/{results['total_tests']}\n"
            report += f"- **Coverage**: {results['coverage']:.1f}%\n"
            report += f"- **Status**: {'PASSED' if results['failed_tests'] == 0 else 'FAILED'}\n\n"
            
            # Детали по файлам
            for test_file in results["test_files"]:
                file_status = "✅" if test_file["status"] == "PASSED" else "❌"
                report += f"  - {file_status} `{test_file['file']}`: {test_file['passed']}/{test_file['total']}\n"
            
            report += "\n"
        
        # Рекомендации
        report += """
## 🔧 Recommendations

"""
        
        if self.results["failed_tests"] > 0:
            report += "- ❌ **Fix failing tests** before deployment\n"
        
        if self.results["security_coverage"] < 90:
            report += "- ⚠️ **Improve test coverage** to at least 90%\n"
        
        if self.results["critical_tests_failed"] > 0:
            report += "- 🚨 **Critical security tests failed** - do not deploy\n"
        
        if self.results["security_coverage"] >= 90 and self.results["failed_tests"] == 0:
            report += "- ✅ **All tests passed** - ready for deployment\n"
        
        report += """
## 🚀 Next Steps

1. Review failing tests
2. Fix any security issues
3. Re-run tests
4. Deploy to staging
5. Schedule penetration testing
"""
        
        return report
    
    def save_results(self):
        """Сохранение результатов"""
        # Сохраняем JSON отчет
        with open(self.workspace_root / "security_test_results.json", "w") as f:
            json.dump(self.results, f, indent=2)
        
        # Сохраняем текстовый отчет
        report = self.generate_test_report()
        with open(self.workspace_root / "SECURITY_TEST_REPORT.md", "w") as f:
            f.write(report)
        
        logger.info("Test results saved to security_test_results.json and SECURITY_TEST_REPORT.md")
    
    def run_tests(self) -> bool:
        """Основная функция запуска тестов"""
        try:
            # Запускаем все тесты
            self.run_all_security_tests()
            
            # Сохраняем результаты
            self.save_results()
            
            # Выводим краткую сводку
            logger.info("="*60)
            logger.info("SECURITY TEST RESULTS SUMMARY")
            logger.info("="*60)
            logger.info(f"Total Tests: {self.results['total_tests']}")
            logger.info(f"Passed: {self.results['passed_tests']} ✅")
            logger.info(f"Failed: {self.results['failed_tests']} ❌")
            logger.info(f"Coverage: {self.results['security_coverage']:.1f}%")
            logger.info(f"Critical Tests: {self.results['critical_tests_passed']}/{self.results['critical_tests_passed'] + self.results['critical_tests_failed']}")
            logger.info("="*60)
            
            # Определяем статус
            if self.results["failed_tests"] == 0 and self.results["security_coverage"] >= 90:
                logger.info("🎉 ALL SECURITY TESTS PASSED - READY FOR DEPLOYMENT!")
                return True
            else:
                logger.error("❌ SOME TESTS FAILED - REVIEW BEFORE DEPLOYMENT")
                return False
                
        except Exception as e:
            logger.error(f"❌ Test execution failed: {e}")
            return False

def main():
    """Основная функция"""
    runner = SecurityTestRunner()
    
    try:
        success = runner.run_tests()
        
        if success:
            logger.info("✅ Security testing completed successfully!")
            sys.exit(0)
        else:
            logger.error("❌ Security testing failed")
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()