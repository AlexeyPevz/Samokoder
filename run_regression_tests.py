#!/usr/bin/env python3
"""
Скрипт для запуска регрессионных тестов с приоритизацией
P0 тесты блокируют мёрж, P1 тесты рекомендуются
"""

import subprocess
import sys
import json
import time
from datetime import datetime
from typing import Dict, List, Tuple
import argparse

class RegressionTestRunner:
    """Запуск регрессионных тестов с приоритизацией"""
    
    def __init__(self):
        self.results = {
            "p0_tests": [],
            "p1_tests": [],
            "p0_passed": 0,
            "p0_failed": 0,
            "p1_passed": 0,
            "p1_failed": 0,
            "start_time": None,
            "end_time": None,
            "total_duration": 0
        }
    
    def run_p0_tests(self) -> Tuple[bool, List[str]]:
        """Запуск P0 тестов (блокирующих мёрж)"""
        print("🚨 Запуск P0 тестов (БЛОКИРУЮЩИХ МЁРЖ)...")
        print("=" * 60)
        
        p0_tests = [
            "test_jwt_token_validation_regression",
            "test_jwt_algorithm_validation_regression", 
            "test_mfa_setup_redis_storage_regression",
            "test_mfa_verification_totp_regression",
            "test_api_key_creation_connection_manager_regression",
            "test_api_key_retrieval_connection_manager_regression"
        ]
        
        failed_tests = []
        
        for test in p0_tests:
            print(f"🧪 Запуск P0 теста: {test}")
            start_time = time.time()
            
            try:
                result = subprocess.run([
                    "python", "-m", "pytest", 
                    f"tests/test_regression_critical_flows.py::{test}",
                    "-v", "--tb=short", "--no-header"
                ], capture_output=True, text=True, timeout=300)
                
                duration = time.time() - start_time
                
                if result.returncode == 0:
                    print(f"✅ {test} - ПРОЙДЕН ({duration:.2f}s)")
                    self.results["p0_passed"] += 1
                    self.results["p0_tests"].append({
                        "name": test,
                        "status": "PASSED",
                        "duration": duration,
                        "output": result.stdout
                    })
                else:
                    print(f"❌ {test} - ПРОВАЛЕН ({duration:.2f}s)")
                    print(f"   Ошибка: {result.stderr}")
                    self.results["p0_failed"] += 1
                    failed_tests.append(test)
                    self.results["p0_tests"].append({
                        "name": test,
                        "status": "FAILED",
                        "duration": duration,
                        "output": result.stdout,
                        "error": result.stderr
                    })
                    
            except subprocess.TimeoutExpired:
                print(f"⏰ {test} - ТАЙМАУТ (300s)")
                self.results["p0_failed"] += 1
                failed_tests.append(test)
                self.results["p0_tests"].append({
                    "name": test,
                    "status": "TIMEOUT",
                    "duration": 300,
                    "error": "Test timeout after 300 seconds"
                })
            except Exception as e:
                print(f"💥 {test} - ОШИБКА: {str(e)}")
                self.results["p0_failed"] += 1
                failed_tests.append(test)
                self.results["p0_tests"].append({
                    "name": test,
                    "status": "ERROR",
                    "duration": 0,
                    "error": str(e)
                })
        
        print("=" * 60)
        print(f"📊 P0 тесты завершены: {self.results['p0_passed']} пройдено, {self.results['p0_failed']} провалено")
        
        return len(failed_tests) == 0, failed_tests
    
    def run_p1_tests(self) -> Tuple[bool, List[str]]:
        """Запуск P1 тестов (рекомендуемых)"""
        print("\n⚠️  Запуск P1 тестов (РЕКОМЕНДУЕМЫХ)...")
        print("=" * 60)
        
        p1_tests = [
            "test_mfa_fallback_in_memory_regression",
            "test_api_key_logging_security_regression",
            "test_end_to_end_authentication_flow_regression",
            "test_api_keys_management_flow_regression"
        ]
        
        failed_tests = []
        
        for test in p1_tests:
            print(f"🧪 Запуск P1 теста: {test}")
            start_time = time.time()
            
            try:
                result = subprocess.run([
                    "python", "-m", "pytest", 
                    f"tests/test_regression_critical_flows.py::{test}",
                    "-v", "--tb=short", "--no-header"
                ], capture_output=True, text=True, timeout=300)
                
                duration = time.time() - start_time
                
                if result.returncode == 0:
                    print(f"✅ {test} - ПРОЙДЕН ({duration:.2f}s)")
                    self.results["p1_passed"] += 1
                    self.results["p1_tests"].append({
                        "name": test,
                        "status": "PASSED",
                        "duration": duration,
                        "output": result.stdout
                    })
                else:
                    print(f"❌ {test} - ПРОВАЛЕН ({duration:.2f}s)")
                    print(f"   Ошибка: {result.stderr}")
                    self.results["p1_failed"] += 1
                    failed_tests.append(test)
                    self.results["p1_tests"].append({
                        "name": test,
                        "status": "FAILED",
                        "duration": duration,
                        "output": result.stdout,
                        "error": result.stderr
                    })
                    
            except subprocess.TimeoutExpired:
                print(f"⏰ {test} - ТАЙМАУТ (300s)")
                self.results["p1_failed"] += 1
                failed_tests.append(test)
                self.results["p1_tests"].append({
                    "name": test,
                    "status": "TIMEOUT",
                    "duration": 300,
                    "error": "Test timeout after 300 seconds"
                })
            except Exception as e:
                print(f"💥 {test} - ОШИБКА: {str(e)}")
                self.results["p1_failed"] += 1
                failed_tests.append(test)
                self.results["p1_tests"].append({
                    "name": test,
                    "status": "ERROR",
                    "duration": 0,
                    "error": str(e)
                })
        
        print("=" * 60)
        print(f"📊 P1 тесты завершены: {self.results['p1_passed']} пройдено, {self.results['p1_failed']} провалено")
        
        return len(failed_tests) == 0, failed_tests
    
    def run_edge_case_tests(self) -> Tuple[bool, List[str]]:
        """Запуск тестов граничных случаев"""
        print("\n🔍 Запуск тестов граничных случаев...")
        print("=" * 60)
        
        edge_tests = [
            "test_connection_manager_failure_regression",
            "test_redis_connection_failure_regression",
            "test_jwt_token_expiration_regression",
            "test_mfa_invalid_code_regression"
        ]
        
        failed_tests = []
        
        for test in edge_tests:
            print(f"🧪 Запуск edge case теста: {test}")
            start_time = time.time()
            
            try:
                result = subprocess.run([
                    "python", "-m", "pytest", 
                    f"tests/test_regression_critical_flows.py::{test}",
                    "-v", "--tb=short", "--no-header"
                ], capture_output=True, text=True, timeout=300)
                
                duration = time.time() - start_time
                
                if result.returncode == 0:
                    print(f"✅ {test} - ПРОЙДЕН ({duration:.2f}s)")
                else:
                    print(f"❌ {test} - ПРОВАЛЕН ({duration:.2f}s)")
                    print(f"   Ошибка: {result.stderr}")
                    failed_tests.append(test)
                    
            except subprocess.TimeoutExpired:
                print(f"⏰ {test} - ТАЙМАУТ (300s)")
                failed_tests.append(test)
            except Exception as e:
                print(f"💥 {test} - ОШИБКА: {str(e)}")
                failed_tests.append(test)
        
        print("=" * 60)
        print(f"📊 Edge case тесты завершены: {len(edge_tests) - len(failed_tests)} пройдено, {len(failed_tests)} провалено")
        
        return len(failed_tests) == 0, failed_tests
    
    def generate_report(self, p0_success: bool, p1_success: bool, edge_success: bool):
        """Генерация отчета о тестировании"""
        self.results["end_time"] = datetime.now().isoformat()
        self.results["total_duration"] = (
            datetime.fromisoformat(self.results["end_time"]) - 
            datetime.fromisoformat(self.results["start_time"])
        ).total_seconds()
        
        print("\n" + "=" * 80)
        print("📋 ОТЧЕТ О РЕГРЕССИОННОМ ТЕСТИРОВАНИИ")
        print("=" * 80)
        
        print(f"🕐 Время начала: {self.results['start_time']}")
        print(f"🕐 Время окончания: {self.results['end_time']}")
        print(f"⏱️  Общая продолжительность: {self.results['total_duration']:.2f} секунд")
        
        print(f"\n🚨 P0 тесты (БЛОКИРУЮЩИЕ МЁРЖ):")
        print(f"   ✅ Пройдено: {self.results['p0_passed']}")
        print(f"   ❌ Провалено: {self.results['p0_failed']}")
        print(f"   📊 Статус: {'ЗЕЛЁНЫЙ' if p0_success else 'КРАСНЫЙ'}")
        
        print(f"\n⚠️  P1 тесты (РЕКОМЕНДУЕМЫЕ):")
        print(f"   ✅ Пройдено: {self.results['p1_passed']}")
        print(f"   ❌ Провалено: {self.results['p1_failed']}")
        print(f"   📊 Статус: {'ЗЕЛЁНЫЙ' if p1_success else 'КРАСНЫЙ'}")
        
        print(f"\n🔍 Edge case тесты:")
        print(f"   📊 Статус: {'ЗЕЛЁНЫЙ' if edge_success else 'КРАСНЫЙ'}")
        
        # Определяем статус мёржа
        if p0_success:
            print(f"\n🎉 СТАТУС МЁРЖА: РАЗРЕШЁН")
            print(f"   ✅ Все P0 тесты пройдены")
            if p1_success:
                print(f"   ✅ Все P1 тесты пройдены")
            else:
                print(f"   ⚠️  Некоторые P1 тесты провалены (не блокируют мёрж)")
        else:
            print(f"\n🚫 СТАТУС МЁРЖА: ЗАБЛОКИРОВАН")
            print(f"   ❌ P0 тесты провалены - мёрж запрещён")
        
        # Сохраняем отчет в файл
        report_file = f"regression_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        print(f"\n📄 Отчет сохранен в файл: {report_file}")
        
        return p0_success
    
    def run_all_tests(self, include_edge_cases: bool = False):
        """Запуск всех регрессионных тестов"""
        self.results["start_time"] = datetime.now().isoformat()
        
        print("🚀 ЗАПУСК РЕГРЕССИОННОГО ТЕСТИРОВАНИЯ")
        print("=" * 80)
        print(f"🕐 Время начала: {self.results['start_time']}")
        print(f"🎯 Цель: Проверка критических пользовательских потоков")
        print(f"📋 Статус: P0 тесты блокируют мёрж, P1 тесты рекомендуются")
        
        # Запускаем P0 тесты
        p0_success, p0_failed = self.run_p0_tests()
        
        # Запускаем P1 тесты
        p1_success, p1_failed = self.run_p1_tests()
        
        # Запускаем edge case тесты (опционально)
        edge_success = True
        if include_edge_cases:
            edge_success, edge_failed = self.run_edge_case_tests()
        
        # Генерируем отчет
        merge_allowed = self.generate_report(p0_success, p1_success, edge_success)
        
        return merge_allowed

def main():
    """Основная функция"""
    parser = argparse.ArgumentParser(description="Запуск регрессионных тестов")
    parser.add_argument("--p0-only", action="store_true", help="Запустить только P0 тесты")
    parser.add_argument("--p1-only", action="store_true", help="Запустить только P1 тесты")
    parser.add_argument("--include-edge-cases", action="store_true", help="Включить тесты граничных случаев")
    parser.add_argument("--verbose", "-v", action="store_true", help="Подробный вывод")
    
    args = parser.parse_args()
    
    runner = RegressionTestRunner()
    
    if args.p0_only:
        print("🚨 Запуск только P0 тестов (блокирующих мёрж)...")
        p0_success, _ = runner.run_p0_tests()
        runner.generate_report(p0_success, True, True)
        return 0 if p0_success else 1
    
    elif args.p1_only:
        print("⚠️  Запуск только P1 тестов (рекомендуемых)...")
        p1_success, _ = runner.run_p1_tests()
        runner.generate_report(True, p1_success, True)
        return 0 if p1_success else 1
    
    else:
        print("🚀 Запуск всех регрессионных тестов...")
        merge_allowed = runner.run_all_tests(include_edge_cases=args.include_edge_cases)
        return 0 if merge_allowed else 1

if __name__ == "__main__":
    exit(main())