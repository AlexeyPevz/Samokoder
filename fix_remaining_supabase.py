#!/usr/bin/env python3
"""
Скрипт для исправления оставшихся вызовов Supabase
"""

def fix_remaining_supabase(file_path):
    """Исправляет оставшиеся вызовы Supabase в файле"""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Заменяем все supabase.table на lambda client: client.table
    content = content.replace('supabase.table(', 'lambda client: client.table(')
    
    # Добавляем "anon" в конец каждого execute_supabase_operation
    import re
    pattern = r'await execute_supabase_operation\(\s*\n\s*lambda client: client\.table\([^)]+\)\.[^)]+\)\s*\n\s*\)'
    
    def add_anon(match):
        return match.group(0).replace(')', ',\n            "anon"\n        )')
    
    content = re.sub(pattern, add_anon, content, flags=re.MULTILINE)
    
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"Fixed {file_path}")

if __name__ == "__main__":
    fix_remaining_supabase("/workspace/backend/api/projects.py")
    print("Done!")