#!/usr/bin/env python3
"""
Скрипт для запуска проекта в режиме разработки
"""

import subprocess
import sys
import os
import time
import signal
from pathlib import Path

def run_backend():
    """Запуск backend сервера"""
    print("🚀 Запуск backend сервера...")
    os.chdir("/workspace")
    return subprocess.Popen([
        sys.executable, "-m", "uvicorn", 
        "backend.main:app", 
        "--host", "0.0.0.0", 
        "--port", "8000", 
        "--reload"
    ])

def run_frontend():
    """Запуск frontend сервера"""
    print("🎨 Запуск frontend сервера...")
    os.chdir("/workspace/frontend")
    return subprocess.Popen([
        "npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "5173"
    ])

def main():
    """Главная функция"""
    print("=" * 60)
    print("🚀 SAMOKODER DEVELOPMENT SERVER")
    print("=" * 60)
    
    # Проверяем зависимости
    print("📋 Проверка зависимостей...")
    
    # Backend
    try:
        import backend.main
        print("✅ Backend зависимости OK")
    except ImportError as e:
        print(f"❌ Backend зависимости: {e}")
        return 1
    
    # Frontend
    frontend_dir = Path("/workspace/frontend")
    if not (frontend_dir / "node_modules").exists():
        print("❌ Frontend зависимости не установлены")
        print("Запустите: cd frontend && npm install")
        return 1
    print("✅ Frontend зависимости OK")
    
    print("\n🌐 Запуск серверов...")
    print("Backend: http://localhost:8000")
    print("Frontend: http://localhost:5173")
    print("API Docs: http://localhost:8000/docs")
    print("\nДля остановки нажмите Ctrl+C")
    print("=" * 60)
    
    # Запускаем процессы
    backend_proc = None
    frontend_proc = None
    
    try:
        backend_proc = run_backend()
        time.sleep(2)  # Даем время backend запуститься
        
        frontend_proc = run_frontend()
        
        # Ждем завершения
        while True:
            time.sleep(1)
            
            # Проверяем, что процессы еще работают
            if backend_proc.poll() is not None:
                print("❌ Backend сервер остановлен")
                break
                
            if frontend_proc.poll() is not None:
                print("❌ Frontend сервер остановлен")
                break
                
    except KeyboardInterrupt:
        print("\n🛑 Остановка серверов...")
        
    finally:
        # Останавливаем процессы
        if backend_proc:
            backend_proc.terminate()
            try:
                backend_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                backend_proc.kill()
                
        if frontend_proc:
            frontend_proc.terminate()
            try:
                frontend_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                frontend_proc.kill()
        
        print("✅ Серверы остановлены")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())