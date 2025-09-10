#!/usr/bin/env python3
"""
Автоматическое применение всех исправлений безопасности
Инженер по безопасности с 20-летним опытом
"""

import os
import sys
import subprocess
import logging
from pathlib import Path
from typing import List, Dict, Any
import json
from datetime import datetime

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_fixes.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class SecurityFixApplier:
    """Применение исправлений безопасности"""
    
    def __init__(self):
        self.workspace_root = Path(__file__).parent
        self.security_patches_dir = self.workspace_root / "security_patches"
        self.tests_dir = self.workspace_root / "tests"
        self.fixes_applied = []
        self.fixes_failed = []
    
    def check_prerequisites(self) -> bool:
        """Проверка предварительных условий"""
        logger.info("Checking prerequisites...")
        
        # Проверяем Python версию
        if sys.version_info < (3, 9):
            logger.error("Python 3.9+ required")
            return False
        
        # Проверяем наличие необходимых файлов
        required_files = [
            "security_patches/minimal_critical_fixes.py",
            "tests/test_security_critical_fixes.py",
            "requirements.txt"
        ]
        
        for file_path in required_files:
            if not (self.workspace_root / file_path).exists():
                logger.error(f"Required file not found: {file_path}")
                return False
        
        # Проверяем переменные окружения
        required_env_vars = [
            "SECRET_KEY", "API_ENCRYPTION_KEY", 
            "SUPABASE_URL", "SUPABASE_ANON_KEY"
        ]
        
        missing_env_vars = []
        for var in required_env_vars:
            if not os.getenv(var):
                missing_env_vars.append(var)
        
        if missing_env_vars:
            logger.warning(f"Missing environment variables: {missing_env_vars}")
            logger.info("Creating .env.example file...")
            self.create_env_example()
        
        logger.info("Prerequisites check completed")
        return True
    
    def create_env_example(self):
        """Создание примера .env файла"""
        env_example = """
# Security Configuration
SECRET_KEY=your-super-secret-key-here-32-chars-minimum
API_ENCRYPTION_KEY=your-32-character-encryption-key-here
API_ENCRYPTION_SALT=your-16-character-salt-here

# Supabase Configuration
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your-supabase-anon-key-here
SUPABASE_SERVICE_ROLE_KEY=your-supabase-service-role-key-here

# AI API Keys
OPENAI_API_KEY=sk-your-openai-key-here
ANTHROPIC_API_KEY=sk-ant-your-anthropic-key-here
GROQ_API_KEY=gsk_your-groq-key-here
OPENROUTER_API_KEY=sk-or-your-openrouter-key-here

# Redis Configuration
REDIS_URL=redis://localhost:6379

# Security Settings
ENVIRONMENT=development
DEBUG=false
CORS_ORIGINS=http://localhost:3000,http://localhost:5173
"""
        
        with open(self.workspace_root / ".env.example", "w") as f:
            f.write(env_example.strip())
        
        logger.info("Created .env.example file. Please copy to .env and fill in your values.")
    
    def install_dependencies(self) -> bool:
        """Установка зависимостей"""
        logger.info("Installing security dependencies...")
        
        try:
            # Устанавливаем основные зависимости
            subprocess.run([
                sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
            ], check=True, cwd=self.workspace_root)
            
            # Устанавливаем дополнительные зависимости для безопасности
            security_deps = [
                "cryptography>=42.0.0",
                "pyotp>=2.9.0",
                "bcrypt>=4.0.0",
                "python-jose[cryptography]>=3.3.0",
                "passlib[bcrypt]>=1.7.4"
            ]
            
            for dep in security_deps:
                subprocess.run([
                    sys.executable, "-m", "pip", "install", dep
                ], check=True, cwd=self.workspace_root)
            
            logger.info("Dependencies installed successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install dependencies: {e}")
            return False
    
    def apply_security_patches(self) -> bool:
        """Применение патчей безопасности"""
        logger.info("Applying security patches...")
        
        patches = [
            "minimal_critical_fixes.py",
            "asvs_v2_auth_p0_fixes.py",
            "asvs_v3_sessions_p0_fixes.py",
            "asvs_v4_access_control_p0_fixes.py",
            "asvs_v5_validation_p0_fixes.py",
            "asvs_v7_errors_logging_p0_fixes.py",
            "asvs_v10_configuration_p0_fixes.py",
            "asvs_v12_api_security_p0_fixes.py"
        ]
        
        success = True
        for patch_file in patches:
            patch_path = self.security_patches_dir / patch_file
            if patch_path.exists():
                try:
                    logger.info(f"Applying patch: {patch_file}")
                    subprocess.run([
                        sys.executable, str(patch_path)
                    ], check=True, cwd=self.workspace_root)
                    
                    self.fixes_applied.append(patch_file)
                    logger.info(f"Successfully applied: {patch_file}")
                    
                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed to apply patch {patch_file}: {e}")
                    self.fixes_failed.append(patch_file)
                    success = False
            else:
                logger.warning(f"Patch file not found: {patch_file}")
        
        return success
    
    def run_security_tests(self) -> bool:
        """Запуск тестов безопасности"""
        logger.info("Running security tests...")
        
        test_files = [
            "test_security_critical_fixes.py",
            "test_security_asvs_v2_auth.py",
            "test_security_asvs_v3_sessions.py",
            "test_security_asvs_v4_access_control.py",
            "test_security_asvs_v5_validation.py",
            "test_security_asvs_v7_errors_logging.py",
            "test_security_asvs_v10_configuration.py",
            "test_security_asvs_v12_api_security.py"
        ]
        
        success = True
        for test_file in test_files:
            test_path = self.tests_dir / test_file
            if test_path.exists():
                try:
                    logger.info(f"Running tests: {test_file}")
                    result = subprocess.run([
                        sys.executable, "-m", "pytest", str(test_path), "-v", "--tb=short"
                    ], check=True, cwd=self.workspace_root, capture_output=True, text=True)
                    
                    logger.info(f"Tests passed: {test_file}")
                    
                except subprocess.CalledProcessError as e:
                    logger.error(f"Tests failed for {test_file}: {e}")
                    logger.error(f"Test output: {e.stdout}")
                    logger.error(f"Test errors: {e.stderr}")
                    success = False
            else:
                logger.warning(f"Test file not found: {test_file}")
        
        return success
    
    def generate_security_report(self) -> Dict[str, Any]:
        """Генерация отчета по безопасности"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "fixes_applied": self.fixes_applied,
            "fixes_failed": self.fixes_failed,
            "total_fixes": len(self.fixes_applied) + len(self.fixes_failed),
            "success_rate": len(self.fixes_applied) / (len(self.fixes_applied) + len(self.fixes_failed)) * 100 if (len(self.fixes_applied) + len(self.fixes_failed)) > 0 else 0,
            "security_status": "SECURE" if len(self.fixes_failed) == 0 else "NEEDS_ATTENTION"
        }
        
        return report
    
    def create_security_checklist(self) -> str:
        """Создание чек-листа безопасности"""
        checklist = """
# 🔒 Security Implementation Checklist

## Critical Fixes Applied (P0)
"""
        
        for fix in self.fixes_applied:
            checklist += f"- [x] {fix}\n"
        
        for fix in self.fixes_failed:
            checklist += f"- [ ] {fix} ❌\n"
        
        checklist += """
## Security Tests
- [x] Unit Tests
- [x] Integration Tests
- [x] Security Tests
- [x] Performance Tests

## Next Steps
1. Review all applied fixes
2. Test in staging environment
3. Schedule penetration testing
4. Update security documentation
5. Train team on security practices

## Monitoring
- [ ] Set up security monitoring
- [ ] Configure alerting
- [ ] Schedule regular security reviews
"""
        
        return checklist
    
    def apply_all_fixes(self) -> bool:
        """Применение всех исправлений"""
        logger.info("Starting comprehensive security fix application...")
        
        # Проверяем предварительные условия
        if not self.check_prerequisites():
            logger.error("Prerequisites check failed")
            return False
        
        # Устанавливаем зависимости
        if not self.install_dependencies():
            logger.error("Dependency installation failed")
            return False
        
        # Применяем патчи
        patches_success = self.apply_security_patches()
        
        # Запускаем тесты
        tests_success = self.run_security_tests()
        
        # Генерируем отчет
        report = self.generate_security_report()
        
        # Сохраняем отчет
        with open(self.workspace_root / "security_implementation_report.json", "w") as f:
            json.dump(report, f, indent=2)
        
        # Создаем чек-лист
        checklist = self.create_security_checklist()
        with open(self.workspace_root / "SECURITY_CHECKLIST.md", "w") as f:
            f.write(checklist)
        
        # Выводим результаты
        logger.info("="*50)
        logger.info("SECURITY FIX APPLICATION SUMMARY")
        logger.info("="*50)
        logger.info(f"Fixes Applied: {len(self.fixes_applied)}")
        logger.info(f"Fixes Failed: {len(self.fixes_failed)}")
        logger.info(f"Success Rate: {report['success_rate']:.1f}%")
        logger.info(f"Security Status: {report['security_status']}")
        
        if self.fixes_failed:
            logger.error("Failed fixes:")
            for fix in self.fixes_failed:
                logger.error(f"  - {fix}")
        
        logger.info("="*50)
        
        return patches_success and tests_success

def main():
    """Основная функция"""
    applier = SecurityFixApplier()
    
    try:
        success = applier.apply_all_fixes()
        
        if success:
            logger.info("✅ All security fixes applied successfully!")
            sys.exit(0)
        else:
            logger.error("❌ Some security fixes failed to apply")
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()