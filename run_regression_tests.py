#!/usr/bin/env python3
"""
Скрипт для запуска регрессионных тестов критических пользовательских потоков
"""

import subprocess
import sys
import json
import time
from datetime import datetime
from pathlib import Path

class RegressionTestRunner:
    """Класс для запуска регрессионных тестов"""
    
    def __init__(self):
        self.results = {
            "start_time": datetime.now().isoformat(),
            "tests": {},
            "summary": {
                "total": 0,
                "passed": 0,
                "failed": 0,
                "skipped": 0,
                "errors": 0
            }
        }
    
    def run_test_file(self, test_file: str, priority: str = "P1") -> dict:
        """Запуск тестового файла"""
        print(f"\n{'='*60}")
        print(f"Запуск тестов: {test_file} (Приоритет: {priority})")
        print(f"{'='*60}")
        
        start_time = time.time()
        
        try:
            # Запускаем pytest для конкретного файла
            result = subprocess.run([
                sys.executable, "-m", "pytest", 
                test_file, 
                "-v", 
                "--tb=short",
                "--json-report",
                "--json-report-file=test_results.json"
            ], capture_output=True, text=True, timeout=300)
            
            end_time = time.time()
            duration = end_time - start_time
            
            # Читаем JSON отчёт
            try:
                with open("test_results.json", "r") as f:
                    json_report = json.load(f)
                
                test_results = {
                    "status": "passed" if result.returncode == 0 else "failed",
                    "duration": duration,
                    "returncode": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "summary": json_report.get("summary", {}),
                    "tests": json_report.get("tests", [])
                }
            except FileNotFoundError:
                test_results = {
                    "status": "failed",
                    "duration": duration,
                    "returncode": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "summary": {},
                    "tests": []
                }
            
            # Обновляем общую статистику
            if test_results["status"] == "passed":
                self.results["summary"]["passed"] += test_results["summary"].get("passed", 0)
            else:
                self.results["summary"]["failed"] += test_results["summary"].get("failed", 0)
            
            self.results["summary"]["total"] += test_results["summary"].get("total", 0)
            self.results["summary"]["skipped"] += test_results["summary"].get("skipped", 0)
            self.results["summary"]["errors"] += test_results["summary"].get("error", 0)
            
            return test_results
            
        except subprocess.TimeoutExpired:
            return {
                "status": "timeout",
                "duration": 300,
                "returncode": -1,
                "stdout": "",
                "stderr": "Test timeout after 5 minutes",
                "summary": {},
                "tests": []
            }
        except Exception as e:
            return {
                "status": "error",
                "duration": 0,
                "returncode": -1,
                "stdout": "",
                "stderr": str(e),
                "summary": {},
                "tests": []
            }
    
    def run_all_tests(self):
        """Запуск всех регрессионных тестов"""
        print("🚀 Запуск регрессионных тестов критических пользовательских потоков")
        print(f"Время начала: {self.results['start_time']}")
        
        # P0 тесты (критические - блокируют мёрж)
        p0_tests = [
            ("tests/test_regression_auth_security.py", "P0"),
            ("tests/test_regression_project_management.py", "P0"),
            ("tests/test_regression_middleware_security.py", "P0")
        ]
        
        # P1 тесты (важные - требуют внимания)
        p1_tests = [
            ("tests/test_regression_ai_service.py", "P1"),
            ("tests/test_regression_critical_user_flows.py", "P1")
        ]
        
        # Запускаем P0 тесты
        print("\n🔴 P0 ТЕСТЫ (Критические - блокируют мёрж)")
        for test_file, priority in p0_tests:
            if Path(test_file).exists():
                result = self.run_test_file(test_file, priority)
                self.results["tests"][test_file] = result
                
                if result["status"] != "passed":
                    print(f"❌ КРИТИЧЕСКАЯ ОШИБКА в {test_file}")
                    print(f"   Статус: {result['status']}")
                    print(f"   Ошибка: {result['stderr'][:200]}...")
            else:
                print(f"⚠️  Файл не найден: {test_file}")
        
        # Запускаем P1 тесты
        print("\n🟡 P1 ТЕСТЫ (Важные - требуют внимания)")
        for test_file, priority in p1_tests:
            if Path(test_file).exists():
                result = self.run_test_file(test_file, priority)
                self.results["tests"][test_file] = result
                
                if result["status"] != "passed":
                    print(f"⚠️  ОШИБКА в {test_file}")
                    print(f"   Статус: {result['status']}")
                    print(f"   Ошибка: {result['stderr'][:200]}...")
            else:
                print(f"⚠️  Файл не найден: {test_file}")
        
        # Завершаем
        self.results["end_time"] = datetime.now().isoformat()
        self.results["duration"] = (
            datetime.fromisoformat(self.results["end_time"]) - 
            datetime.fromisoformat(self.results["start_time"])
        ).total_seconds()
        
        self.print_summary()
        self.save_results()
    
    def print_summary(self):
        """Вывод сводки результатов"""
        print(f"\n{'='*60}")
        print("📊 СВОДКА РЕЗУЛЬТАТОВ РЕГРЕССИОННОГО ТЕСТИРОВАНИЯ")
        print(f"{'='*60}")
        
        summary = self.results["summary"]
        total = summary["total"]
        passed = summary["passed"]
        failed = summary["failed"]
        skipped = summary["skipped"]
        errors = summary["errors"]
        
        print(f"Всего тестов: {total}")
        print(f"✅ Прошло: {passed}")
        print(f"❌ Провалено: {failed}")
        print(f"⏭️  Пропущено: {skipped}")
        print(f"💥 Ошибок: {errors}")
        
        if total > 0:
            success_rate = (passed / total) * 100
            print(f"📈 Процент успеха: {success_rate:.1f}%")
        
        print(f"⏱️  Общее время выполнения: {self.results['duration']:.2f} секунд")
        
        # Проверяем критические ошибки
        critical_failures = []
        for test_file, result in self.results["tests"].items():
            if "P0" in test_file and result["status"] != "passed":
                critical_failures.append(test_file)
        
        if critical_failures:
            print(f"\n🚨 КРИТИЧЕСКИЕ ОШИБКИ (P0) - МЁРЖ ЗАБЛОКИРОВАН:")
            for test_file in critical_failures:
                print(f"   ❌ {test_file}")
        else:
            print(f"\n✅ Все критические тесты (P0) прошли успешно!")
        
        # Рекомендации
        print(f"\n📋 РЕКОМЕНДАЦИИ:")
        if critical_failures:
            print("   🔴 Исправьте критические ошибки перед мёржем")
        if failed > 0:
            print("   🟡 Исправьте ошибки P1 тестов перед релизом")
        if success_rate >= 95:
            print("   ✅ Отличное качество кода!")
        elif success_rate >= 80:
            print("   ⚠️  Хорошее качество, но есть место для улучшений")
        else:
            print("   🔴 Требуется серьёзная работа над качеством кода")
    
    def save_results(self):
        """Сохранение результатов в файл"""
        results_file = f"regression_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(results_file, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 Результаты сохранены в файл: {results_file}")
        
        # Создаём краткий отчёт
        self.create_summary_report()
    
    def create_summary_report(self):
        """Создание краткого отчёта"""
        report_file = "REGRESSION_TEST_SUMMARY.md"
        
        with open(report_file, "w", encoding="utf-8") as f:
            f.write("# Регрессионное тестирование - Краткий отчёт\n\n")
            f.write(f"**Дата выполнения:** {self.results['start_time']}\n")
            f.write(f"**Общее время:** {self.results['duration']:.2f} секунд\n\n")
            
            summary = self.results["summary"]
            f.write("## Статистика\n\n")
            f.write(f"- Всего тестов: {summary['total']}\n")
            f.write(f"- Прошло: {summary['passed']}\n")
            f.write(f"- Провалено: {summary['failed']}\n")
            f.write(f"- Пропущено: {summary['skipped']}\n")
            f.write(f"- Ошибок: {summary['errors']}\n\n")
            
            if summary['total'] > 0:
                success_rate = (summary['passed'] / summary['total']) * 100
                f.write(f"- Процент успеха: {success_rate:.1f}%\n\n")
            
            f.write("## Результаты по файлам\n\n")
            for test_file, result in self.results["tests"].items():
                status_emoji = "✅" if result["status"] == "passed" else "❌"
                f.write(f"- {status_emoji} {test_file}: {result['status']}\n")
            
            f.write("\n## Рекомендации\n\n")
            
            critical_failures = [
                test_file for test_file, result in self.results["tests"].items()
                if "P0" in test_file and result["status"] != "passed"
            ]
            
            if critical_failures:
                f.write("🔴 **КРИТИЧЕСКИЕ ОШИБКИ (P0) - МЁРЖ ЗАБЛОКИРОВАН:**\n")
                for test_file in critical_failures:
                    f.write(f"- {test_file}\n")
                f.write("\n")
            
            if summary['failed'] > 0:
                f.write("🟡 **Ошибки P1 тестов требуют внимания перед релизом**\n\n")
            
            if summary['total'] > 0 and (summary['passed'] / summary['total']) >= 0.95:
                f.write("✅ **Отличное качество кода!**\n")
            elif summary['total'] > 0 and (summary['passed'] / summary['total']) >= 0.8:
                f.write("⚠️ **Хорошее качество, но есть место для улучшений**\n")
            else:
                f.write("🔴 **Требуется серьёзная работа над качеством кода**\n")
        
        print(f"📄 Краткий отчёт создан: {report_file}")

def main():
    """Основная функция"""
    runner = RegressionTestRunner()
    
    try:
        runner.run_all_tests()
        
        # Проверяем критические ошибки
        critical_failures = [
            test_file for test_file, result in runner.results["tests"].items()
            if "P0" in test_file and result["status"] != "passed"
        ]
        
        if critical_failures:
            print(f"\n🚨 ОБНАРУЖЕНЫ КРИТИЧЕСКИЕ ОШИБКИ!")
            print("Мёрж заблокирован до исправления ошибок P0 тестов.")
            sys.exit(1)
        else:
            print(f"\n✅ Все критические тесты прошли успешно!")
            print("Мёрж разрешён.")
            sys.exit(0)
            
    except KeyboardInterrupt:
        print(f"\n⏹️  Тестирование прервано пользователем")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Ошибка при выполнении тестов: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()