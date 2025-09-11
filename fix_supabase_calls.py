#!/usr/bin/env python3
"""
Скрипт для исправления вызовов Supabase в роутерах
"""

import re

def fix_supabase_calls(file_path):
    """Исправляет вызовы Supabase в файле"""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Удаляем строки с connection_pool_manager
    content = re.sub(r'        supabase = connection_pool_manager\.get_supabase_client\(\)\n', '', content)
    
    # Исправляем вызовы execute_supabase_operation
    # Паттерн: await execute_supabase_operation(\n            supabase.table(...)\n        )
    pattern = r'await execute_supabase_operation\(\s*\n\s*supabase\.table\(([^)]+)\)\.([^)]+)\)\s*\n\s*\)'
    
    def replace_call(match):
        table_call = match.group(1)
        method_call = match.group(2)
        return f'await execute_supabase_operation(\n            lambda client: client.table({table_call}).{method_call},\n            "anon"\n        )'
    
    content = re.sub(pattern, replace_call, content, flags=re.MULTILINE)
    
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"Fixed {file_path}")

if __name__ == "__main__":
    fix_supabase_calls("/workspace/backend/api/projects.py")
    print("Done!")