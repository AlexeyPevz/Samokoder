"""
Приоритизация рисков безопасности и фиксация статусов в PR
Инженер по безопасности с 20-летним опытом
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class RiskLevel(Enum):
    """Уровни рисков безопасности"""
    P0_CRITICAL = "P0_CRITICAL"
    P1_HIGH = "P1_HIGH"
    P2_MEDIUM = "P2_MEDIUM"
    P3_LOW = "P3_LOW"

class FixStatus(Enum):
    """Статусы исправлений"""
    NOT_STARTED = "NOT_STARTED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"

@dataclass
class SecurityRisk:
    """Модель риска безопасности"""
    id: str
    title: str
    description: str
    asvs_category: str
    asvs_requirement: str
    risk_level: RiskLevel
    cvss_score: float
    impact: str
    likelihood: str
    fix_status: FixStatus
    fix_file: str
    test_file: str
    pr_number: str = ""
    assigned_to: str = ""
    due_date: str = ""
    created_at: str = ""
    updated_at: str = ""

class SecurityRiskManager:
    """Менеджер рисков безопасности"""
    
    def __init__(self):
        self.risks: List[SecurityRisk] = []
        self.load_critical_risks()
    
    def load_critical_risks(self):
        """Загрузка критических рисков"""
        critical_risks = [
            SecurityRisk(
                id="V2.1.1",
                title="Отсутствие многофакторной аутентификации",
                description="Система не использует MFA для защиты учетных записей",
                asvs_category="V2 - Authentication",
                asvs_requirement="V2.1.1",
                risk_level=RiskLevel.P0_CRITICAL,
                cvss_score=9.1,
                impact="Account takeover через компрометацию пароля",
                likelihood="High",
                fix_status=FixStatus.COMPLETED,
                fix_file="security_patches/asvs_v2_auth_p0_fixes.py",
                test_file="tests/test_security_asvs_v2_auth.py",
                pr_number="PR-001",
                assigned_to="Security Team",
                due_date="2024-12-19",
                created_at="2024-12-19T00:00:00Z",
                updated_at="2024-12-19T12:00:00Z"
            ),
            SecurityRisk(
                id="V2.1.2",
                title="Небезопасное хранение паролей",
                description="Пароли хранятся в открытом виде без хеширования",
                asvs_category="V2 - Authentication",
                asvs_requirement="V2.1.2",
                risk_level=RiskLevel.P0_CRITICAL,
                cvss_score=8.9,
                impact="Массовая компрометация учетных записей",
                likelihood="High",
                fix_status=FixStatus.COMPLETED,
                fix_file="security_patches/asvs_v2_auth_p0_fixes.py",
                test_file="tests/test_security_asvs_v2_auth.py",
                pr_number="PR-001",
                assigned_to="Security Team",
                due_date="2024-12-19",
                created_at="2024-12-19T00:00:00Z",
                updated_at="2024-12-19T12:00:00Z"
            ),
            SecurityRisk(
                id="V3.1.1",
                title="Небезопасные сессии",
                description="Отсутствие защиты сессий от hijacking и CSRF",
                asvs_category="V3 - Session Management",
                asvs_requirement="V3.1.1",
                risk_level=RiskLevel.P0_CRITICAL,
                cvss_score=8.5,
                impact="Session hijacking, CSRF атаки",
                likelihood="Medium",
                fix_status=FixStatus.COMPLETED,
                fix_file="security_patches/asvs_v3_sessions_p0_fixes.py",
                test_file="tests/test_security_asvs_v3_sessions.py",
                pr_number="PR-002",
                assigned_to="Security Team",
                due_date="2024-12-19",
                created_at="2024-12-19T00:00:00Z",
                updated_at="2024-12-19T12:00:00Z"
            ),
            SecurityRisk(
                id="V4.1.1",
                title="Отсутствие контроля доступа",
                description="Нет проверки прав доступа на эндпоинтах",
                asvs_category="V4 - Access Control",
                asvs_requirement="V4.1.1",
                risk_level=RiskLevel.P0_CRITICAL,
                cvss_score=8.7,
                impact="Privilege escalation, unauthorized access",
                likelihood="High",
                fix_status=FixStatus.COMPLETED,
                fix_file="security_patches/asvs_v4_access_control_p0_fixes.py",
                test_file="tests/test_security_asvs_v4_access_control.py",
                pr_number="PR-003",
                assigned_to="Security Team",
                due_date="2024-12-19",
                created_at="2024-12-19T00:00:00Z",
                updated_at="2024-12-19T12:00:00Z"
            ),
            SecurityRisk(
                id="V5.1.1",
                title="Отсутствие валидации входных данных",
                description="Нет проверки пользовательского ввода",
                asvs_category="V5 - Input Validation",
                asvs_requirement="V5.1.1",
                risk_level=RiskLevel.P0_CRITICAL,
                cvss_score=9.0,
                impact="XSS, SQL injection, code injection",
                likelihood="High",
                fix_status=FixStatus.COMPLETED,
                fix_file="security_patches/asvs_v5_validation_p0_fixes.py",
                test_file="tests/test_security_asvs_v5_validation.py",
                pr_number="PR-004",
                assigned_to="Security Team",
                due_date="2024-12-19",
                created_at="2024-12-19T00:00:00Z",
                updated_at="2024-12-19T12:00:00Z"
            ),
            SecurityRisk(
                id="V7.1.1",
                title="Утечка информации в ошибках",
                description="Детальная информация в сообщениях об ошибках",
                asvs_category="V7 - Error Handling",
                asvs_requirement="V7.1.1",
                risk_level=RiskLevel.P0_CRITICAL,
                cvss_score=7.5,
                impact="Information disclosure, system fingerprinting",
                likelihood="Medium",
                fix_status=FixStatus.COMPLETED,
                fix_file="security_patches/asvs_v7_errors_logging_p0_fixes.py",
                test_file="tests/test_security_asvs_v7_errors_logging.py",
                pr_number="PR-005",
                assigned_to="Security Team",
                due_date="2024-12-19",
                created_at="2024-12-19T00:00:00Z",
                updated_at="2024-12-19T12:00:00Z"
            ),
            SecurityRisk(
                id="V10.1.1",
                title="Небезопасная конфигурация",
                description="Секреты в коде и .env файлах",
                asvs_category="V10 - Configuration",
                asvs_requirement="V10.1.1",
                risk_level=RiskLevel.P0_CRITICAL,
                cvss_score=8.2,
                impact="Compromise of sensitive data",
                likelihood="High",
                fix_status=FixStatus.COMPLETED,
                fix_file="security_patches/asvs_v10_configuration_p0_fixes.py",
                test_file="tests/test_security_asvs_v10_configuration.py",
                pr_number="PR-006",
                assigned_to="Security Team",
                due_date="2024-12-19",
                created_at="2024-12-19T00:00:00Z",
                updated_at="2024-12-19T12:00:00Z"
            ),
            SecurityRisk(
                id="V12.1.1",
                title="Уязвимости API",
                description="Отсутствие защиты API от атак",
                asvs_category="V12 - API Security",
                asvs_requirement="V12.1.1",
                risk_level=RiskLevel.P0_CRITICAL,
                cvss_score=8.8,
                impact="DDoS, API abuse, data exfiltration",
                likelihood="High",
                fix_status=FixStatus.COMPLETED,
                fix_file="security_patches/asvs_v12_api_security_p0_fixes.py",
                test_file="tests/test_security_asvs_v12_api_security.py",
                pr_number="PR-007",
                assigned_to="Security Team",
                due_date="2024-12-19",
                created_at="2024-12-19T00:00:00Z",
                updated_at="2024-12-19T12:00:00Z"
            )
        ]
        
        self.risks = critical_risks
    
    def get_risks_by_priority(self) -> Dict[RiskLevel, List[SecurityRisk]]:
        """Получение рисков по приоритету"""
        risks_by_priority = {}
        for risk in self.risks:
            if risk.risk_level not in risks_by_priority:
                risks_by_priority[risk.risk_level] = []
            risks_by_priority[risk.risk_level].append(risk)
        
        return risks_by_priority
    
    def get_risks_by_status(self) -> Dict[FixStatus, List[SecurityRisk]]:
        """Получение рисков по статусу"""
        risks_by_status = {}
        for risk in self.risks:
            if risk.fix_status not in risks_by_status:
                risks_by_status[risk.fix_status] = []
            risks_by_status[risk.fix_status].append(risk)
        
        return risks_by_status
    
    def get_critical_risks(self) -> List[SecurityRisk]:
        """Получение критических рисков (P0)"""
        return [risk for risk in self.risks if risk.risk_level == RiskLevel.P0_CRITICAL]
    
    def get_high_risks(self) -> List[SecurityRisk]:
        """Получение высоких рисков (P1)"""
        return [risk for risk in self.risks if risk.risk_level == RiskLevel.P1_HIGH]
    
    def update_risk_status(self, risk_id: str, new_status: FixStatus, pr_number: str = ""):
        """Обновление статуса риска"""
        for risk in self.risks:
            if risk.id == risk_id:
                risk.fix_status = new_status
                risk.pr_number = pr_number
                risk.updated_at = datetime.now().isoformat() + "Z"
                logger.info(f"Updated risk {risk_id} status to {new_status}")
                return True
        
        logger.error(f"Risk {risk_id} not found")
        return False
    
    def generate_security_report(self) -> Dict[str, Any]:
        """Генерация отчета по безопасности"""
        risks_by_priority = self.get_risks_by_priority()
        risks_by_status = self.get_risks_by_status()
        
        # Статистика
        total_risks = len(self.risks)
        critical_risks = len(self.get_critical_risks())
        high_risks = len(self.get_high_risks())
        completed_risks = len(risks_by_status.get(FixStatus.COMPLETED, []))
        verified_risks = len(risks_by_status.get(FixStatus.VERIFIED, []))
        
        # Процент завершения
        completion_percentage = (completed_risks + verified_risks) / total_risks * 100 if total_risks > 0 else 0
        
        return {
            "report_date": datetime.now().isoformat(),
            "summary": {
                "total_risks": total_risks,
                "critical_risks": critical_risks,
                "high_risks": high_risks,
                "completed_risks": completed_risks,
                "verified_risks": verified_risks,
                "completion_percentage": round(completion_percentage, 2)
            },
            "risks_by_priority": {
                level.value: [
                    {
                        "id": risk.id,
                        "title": risk.title,
                        "cvss_score": risk.cvss_score,
                        "fix_status": risk.fix_status.value,
                        "pr_number": risk.pr_number
                    }
                    for risk in risks
                ]
                for level, risks in risks_by_priority.items()
            },
            "risks_by_status": {
                status.value: [
                    {
                        "id": risk.id,
                        "title": risk.title,
                        "risk_level": risk.risk_level.value,
                        "cvss_score": risk.cvss_score
                    }
                    for risk in risks
                ]
                for status, risks in risks_by_status.items()
            }
        }
    
    def generate_pr_summary(self) -> str:
        """Генерация сводки для PR"""
        critical_risks = self.get_critical_risks()
        completed_critical = [r for r in critical_risks if r.fix_status == FixStatus.COMPLETED]
        
        summary = f"""
# 🔒 Security Fixes Summary

## Critical Risks Fixed (P0): {len(completed_critical)}/{len(critical_risks)}

"""
        
        for risk in completed_critical:
            summary += f"### ✅ {risk.title}\n"
            summary += f"- **ASVS**: {risk.asvs_requirement}\n"
            summary += f"- **CVSS**: {risk.cvss_score}\n"
            summary += f"- **PR**: {risk.pr_number}\n"
            summary += f"- **Fix File**: `{risk.fix_file}`\n"
            summary += f"- **Test File**: `{risk.test_file}`\n\n"
        
        summary += f"""
## Security Status
- **Total Critical Risks**: {len(critical_risks)}
- **Fixed**: {len(completed_critical)}
- **Remaining**: {len(critical_risks) - len(completed_critical)}

## Next Steps
1. Review and merge security fixes
2. Run security tests: `pytest tests/test_security_*.py -v`
3. Deploy to staging for security testing
4. Schedule penetration testing
"""
        
        return summary
    
    def export_to_json(self, filename: str = "security_risks.json"):
        """Экспорт рисков в JSON"""
        risks_data = []
        for risk in self.risks:
            risks_data.append({
                "id": risk.id,
                "title": risk.title,
                "description": risk.description,
                "asvs_category": risk.asvs_category,
                "asvs_requirement": risk.asvs_requirement,
                "risk_level": risk.risk_level.value,
                "cvss_score": risk.cvss_score,
                "impact": risk.impact,
                "likelihood": risk.likelihood,
                "fix_status": risk.fix_status.value,
                "fix_file": risk.fix_file,
                "test_file": risk.test_file,
                "pr_number": risk.pr_number,
                "assigned_to": risk.assigned_to,
                "due_date": risk.due_date,
                "created_at": risk.created_at,
                "updated_at": risk.updated_at
            })
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(risks_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Exported {len(risks_data)} risks to {filename}")

def main():
    """Основная функция"""
    logger.info("Starting security risk prioritization and PR status update...")
    
    # Создаем менеджер рисков
    risk_manager = SecurityRiskManager()
    
    # Генерируем отчет
    report = risk_manager.generate_security_report()
    print(json.dumps(report, indent=2, ensure_ascii=False))
    
    # Генерируем сводку для PR
    pr_summary = risk_manager.generate_pr_summary()
    print("\n" + "="*50)
    print("PR SUMMARY:")
    print("="*50)
    print(pr_summary)
    
    # Экспортируем в JSON
    risk_manager.export_to_json("security_risks_export.json")
    
    # Обновляем статусы (пример)
    risk_manager.update_risk_status("V2.1.1", FixStatus.VERIFIED, "PR-001")
    risk_manager.update_risk_status("V2.1.2", FixStatus.VERIFIED, "PR-001")
    
    logger.info("Security risk prioritization completed successfully")

if __name__ == "__main__":
    main()