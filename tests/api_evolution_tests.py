"""
Тесты для проверки эволюции API без breaking changes
API Owner - 20 лет опыта
"""

import pytest
import requests
import json
from typing import Dict, Any, List
from datetime import datetime, timedelta
import yaml

class APIEvolutionValidator:
    """Валидатор эволюции API"""
    
    def __init__(self, base_url: str, openapi_spec_path: str):
        self.base_url = base_url.rstrip('/')
        self.openapi_spec = self._load_openapi_spec(openapi_spec_path)
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
    
    def _load_openapi_spec(self, spec_path: str) -> Dict[str, Any]:
        """Загружает OpenAPI спецификацию"""
        with open(spec_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    
    def check_backward_compatibility(self, endpoint: str, method: str) -> Dict[str, Any]:
        """Проверяет обратную совместимость эндпоинта"""
        method = method.lower()
        if endpoint not in self.openapi_spec.get('paths', {}):
            return {"error": "Endpoint not found in spec"}
        
        endpoint_spec = self.openapi_spec['paths'][endpoint]
        if method not in endpoint_spec:
            return {"error": "Method not found in spec"}
        
        spec = endpoint_spec[method]
        compatibility_report = {
            "endpoint": f"{method.upper()} {endpoint}",
            "deprecated_fields": [],
            "deprecated_parameters": [],
            "deprecated_responses": [],
            "breaking_changes": [],
            "recommendations": []
        }
        
        # Проверяем deprecated поля в схемах ответов
        for status_code, response_info in spec.get('responses', {}).items():
            response_schema = response_info.get('content', {}).get('application/json', {}).get('schema')
            if response_schema:
                deprecated_fields = self._find_deprecated_fields(response_schema)
                compatibility_report["deprecated_fields"].extend(deprecated_fields)
        
        # Проверяем deprecated параметры
        for param in spec.get('parameters', []):
            if param.get('deprecated', False):
                compatibility_report["deprecated_parameters"].append({
                    "name": param.get('name'),
                    "in": param.get('in'),
                    "deprecated_since": param.get('x-deprecation-info', {}).get('deprecated_since'),
                    "removal_version": param.get('x-deprecation-info', {}).get('removal_version')
                })
        
        return compatibility_report
    
    def _find_deprecated_fields(self, schema: Dict[str, Any], path: str = "") -> List[Dict[str, Any]]:
        """Рекурсивно находит deprecated поля"""
        deprecated_fields = []
        
        if not isinstance(schema, dict):
            return deprecated_fields
        
        for field_name, field_schema in schema.get('properties', {}).items():
            current_path = f"{path}.{field_name}" if path else field_name
            
            if field_schema.get('deprecated', False):
                deprecated_fields.append({
                    "path": current_path,
                    "deprecated_since": field_schema.get('x-deprecation-info', {}).get('deprecated_since'),
                    "removal_version": field_schema.get('x-deprecation-info', {}).get('removal_version'),
                    "reason": field_schema.get('x-deprecation-info', {}).get('reason'),
                    "replacement": field_schema.get('x-deprecation-info', {}).get('replacement')
                })
            
            # Проверяем вложенные объекты
            if 'properties' in field_schema:
                deprecated_fields.extend(
                    self._find_deprecated_fields(field_schema, current_path)
                )
        
        return deprecated_fields
    
    def generate_migration_guide(self, endpoint: str, method: str) -> str:
        """Генерирует руководство по миграции для эндпоинта"""
        compatibility_report = self.check_backward_compatibility(endpoint, method)
        
        if "error" in compatibility_report:
            return f"Error: {compatibility_report['error']}"
        
        guide = f"# Migration Guide for {compatibility_report['endpoint']}\n\n"
        
        if compatibility_report["deprecated_fields"]:
            guide += "## Deprecated Fields\n\n"
            for field in compatibility_report["deprecated_fields"]:
                guide += f"### {field['path']}\n"
                guide += f"- **Deprecated since:** {field['deprecated_since']}\n"
                guide += f"- **Removal version:** {field['removal_version']}\n"
                guide += f"- **Reason:** {field['reason']}\n"
                guide += f"- **Replacement:** {field['replacement']}\n\n"
        
        if compatibility_report["deprecated_parameters"]:
            guide += "## Deprecated Parameters\n\n"
            for param in compatibility_report["deprecated_parameters"]:
                guide += f"### {param['name']} (in {param['in']})\n"
                guide += f"- **Deprecated since:** {param['deprecated_since']}\n"
                guide += f"- **Removal version:** {param['removal_version']}\n\n"
        
        return guide
    
    def check_version_compatibility(self, current_version: str, target_version: str) -> Dict[str, Any]:
        """Проверяет совместимость между версиями API"""
        # Простая проверка семантического версионирования
        current_parts = current_version.split('.')
        target_parts = target_version.split('.')
        
        compatibility = {
            "current_version": current_version,
            "target_version": target_version,
            "breaking_changes": False,
            "new_features": False,
            "bug_fixes": False,
            "recommendations": []
        }
        
        if len(current_parts) >= 3 and len(target_parts) >= 3:
            current_major = int(current_parts[0])
            current_minor = int(current_parts[1])
            target_major = int(target_parts[0])
            target_minor = int(target_parts[1])
            
            if target_major > current_major:
                compatibility["breaking_changes"] = True
                compatibility["recommendations"].append("Major version upgrade - review breaking changes")
            elif target_minor > current_minor:
                compatibility["new_features"] = True
                compatibility["recommendations"].append("Minor version upgrade - new features available")
            else:
                compatibility["bug_fixes"] = True
                compatibility["recommendations"].append("Patch version upgrade - bug fixes only")
        
        return compatibility

class DeprecationMonitor:
    """Мониторинг использования deprecated полей"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.usage_stats = {}
    
    def track_deprecated_field_usage(self, endpoint: str, field_path: str, usage_count: int = 1):
        """Отслеживает использование deprecated полей"""
        key = f"{endpoint}:{field_path}"
        if key not in self.usage_stats:
            self.usage_stats[key] = {
                "endpoint": endpoint,
                "field_path": field_path,
                "usage_count": 0,
                "first_seen": datetime.now(),
                "last_seen": datetime.now()
            }
        
        self.usage_stats[key]["usage_count"] += usage_count
        self.usage_stats[key]["last_seen"] = datetime.now()
    
    def get_usage_report(self) -> Dict[str, Any]:
        """Генерирует отчет об использовании deprecated полей"""
        report = {
            "total_deprecated_fields": len(self.usage_stats),
            "most_used_fields": [],
            "fields_by_endpoint": {},
            "recommendations": []
        }
        
        # Сортируем по количеству использований
        sorted_fields = sorted(
            self.usage_stats.items(),
            key=lambda x: x[1]["usage_count"],
            reverse=True
        )
        
        report["most_used_fields"] = [
            {
                "field": field_data["field_path"],
                "endpoint": field_data["endpoint"],
                "usage_count": field_data["usage_count"],
                "last_seen": field_data["last_seen"].isoformat()
            }
            for field_key, field_data in sorted_fields[:10]
        ]
        
        # Группируем по эндпоинтам
        for field_key, field_data in self.usage_stats.items():
            endpoint = field_data["endpoint"]
            if endpoint not in report["fields_by_endpoint"]:
                report["fields_by_endpoint"][endpoint] = []
            
            report["fields_by_endpoint"][endpoint].append({
                "field": field_data["field_path"],
                "usage_count": field_data["usage_count"]
            })
        
        # Генерируем рекомендации
        high_usage_fields = [f for f in sorted_fields if f[1]["usage_count"] > 100]
        if high_usage_fields:
            report["recommendations"].append(
                f"High usage detected for {len(high_usage_fields)} deprecated fields. "
                "Consider extending deprecation timeline or providing migration tools."
            )
        
        return report

def test_api_evolution():
    """Тест эволюции API"""
    validator = APIEvolutionValidator("http://localhost:8000", "api/openapi_spec.yaml")
    
    # Тестируем основные эндпоинты
    endpoints_to_test = [
        ("/api/auth/login", "POST"),
        ("/api/auth/register", "POST"),
        ("/api/projects", "GET"),
        ("/api/projects", "POST"),
        ("/api/ai/chat", "POST"),
        ("/api/ai/providers", "GET")
    ]
    
    for endpoint, method in endpoints_to_test:
        print(f"Checking evolution for {method} {endpoint}")
        compatibility_report = validator.check_backward_compatibility(endpoint, method)
        
        if "error" not in compatibility_report:
            print(f"  Deprecated fields: {len(compatibility_report['deprecated_fields'])}")
            print(f"  Deprecated parameters: {len(compatibility_report['deprecated_parameters'])}")
            
            # Генерируем руководство по миграции
            migration_guide = validator.generate_migration_guide(endpoint, method)
            if len(migration_guide) > 100:  # Если есть что мигрировать
                print(f"  Migration guide generated ({len(migration_guide)} chars)")
        else:
            print(f"  Error: {compatibility_report['error']}")

def test_deprecation_monitoring():
    """Тест мониторинга deprecated полей"""
    monitor = DeprecationMonitor("http://localhost:8000")
    
    # Симулируем использование deprecated полей
    monitor.track_deprecated_field_usage("/api/auth/login", "refresh_token", 50)
    monitor.track_deprecated_field_usage("/api/projects", "file_count", 25)
    monitor.track_deprecated_field_usage("/api/ai/chat", "tokens_used", 100)
    
    report = monitor.get_usage_report()
    print(f"Deprecation monitoring report:")
    print(f"  Total deprecated fields: {report['total_deprecated_fields']}")
    print(f"  Most used fields: {len(report['most_used_fields'])}")
    print(f"  Recommendations: {len(report['recommendations'])}")

if __name__ == "__main__":
    test_api_evolution()
    test_deprecation_monitoring()