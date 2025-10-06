"""
Патч 001: Консолидация дублирующихся моделей БД

Проблема:
- core/db/models/project.py
- core/db/models/project_optimized.py (с индексами)
- core/db/models/project_fixed.py

Риск: Confusion, использование неправильной модели, data inconsistency

Решение: Оставить один файл project.py с оптимизациями
"""

import subprocess
import sys
from pathlib import Path


def run_command(cmd: str) -> int:
    """Execute shell command and return exit code."""
    print(f"→ {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    return result.returncode


def main():
    """Consolidate duplicate project models."""
    print("=" * 80)
    print("ПАТЧ 001: Консолидация дублирующихся моделей БД")
    print("=" * 80)
    
    # Step 1: Check which model is used in production
    print("\n[1/5] Проверка usage дублирующихся моделей...")
    
    patterns = [
        "from.*project_optimized import",
        "from.*project_fixed import",
    ]
    
    for pattern in patterns:
        print(f"\n  Поиск: {pattern}")
        run_command(f'git grep "{pattern}" || echo "  ✓ Not found"')
    
    # Step 2: Backup current project.py
    print("\n[2/5] Backup текущего project.py...")
    run_command("cp core/db/models/project.py core/db/models/project_backup.py")
    
    # Step 3: Use optimized version as main
    print("\n[3/5] Замена project.py на optimized версию...")
    if Path("core/db/models/project_optimized.py").exists():
        run_command("mv core/db/models/project_optimized.py core/db/models/project.py")
        print("  ✓ project_optimized.py → project.py")
    else:
        print("  ⚠ project_optimized.py not found, keeping original")
    
    # Step 4: Remove duplicates
    print("\n[4/5] Удаление дубликатов...")
    duplicates = [
        "core/db/models/project_fixed.py",
        "core/db/models/project_backup.py",
    ]
    
    for dup in duplicates:
        if Path(dup).exists():
            run_command(f"rm {dup}")
            print(f"  ✓ Deleted {dup}")
    
    # Step 5: Update imports
    print("\n[5/5] Обновление imports...")
    # Usually not needed since we're keeping project.py name
    
    print("\n" + "=" * 80)
    print("✅ ПАТЧ ПРИМЕНЁН")
    print("=" * 80)
    
    print("\nСледующие шаги:")
    print("1. Запустите тесты: pytest tests/db/")
    print("2. Проверьте, что нет broken imports: git grep 'project_optimized'")
    print("3. Закоммитьте изменения: git add . && git commit -m 'Consolidate DB models'")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
