"""
Мониторинг изменений API для обеспечения обратной совместимости
"""

import requests
import json
import yaml
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class APIChangeMonitor:
    """Мониторинг изменений API"""
    
    def __init__(self, base_url: str, spec_file: str = "openapi.yaml"):
        self.base_url = base_url
        self.spec_file = spec_file
        self.last_spec = None
        self.change_log = []
    
    def load_spec_from_file(self) -> Dict[str, Any]:
        """Загрузка спецификации из файла"""
        try:
            with open(self.spec_file, "r") as f:
                if self.spec_file.endswith(".yaml") or self.spec_file.endswith(".yml"):
                    return yaml.safe_load(f)
                else:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Error loading spec from file: {e}")
            return {}
    
    def load_spec_from_api(self) -> Dict[str, Any]:
        """Загрузка спецификации из API"""
        try:
            response = requests.get(f"{self.base_url}/openapi.json")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Error loading spec from API: {e}")
            return {}
    
    def check_for_changes(self, use_file: bool = True) -> List[Dict[str, Any]]:
        """Проверка изменений в API"""
        try:
            # Получаем текущую спецификацию
            if use_file:
                current_spec = self.load_spec_from_file()
            else:
                current_spec = self.load_spec_from_api()
            
            if not current_spec:
                logger.warning("Could not load current specification")
                return []
            
            if self.last_spec:
                changes = self._detect_changes(self.last_spec, current_spec)
                if changes:
                    self._report_changes(changes)
                    self.change_log.extend(changes)
            
            self.last_spec = current_spec
            return self.change_log
            
        except Exception as e:
            logger.error(f"Error checking API changes: {e}")
            return []
    
    def _detect_changes(self, old_spec: Dict[str, Any], new_spec: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Детекция изменений в спецификации"""
        changes = []
        
        # Проверяем изменения в путях
        old_paths = set(old_spec.get("paths", {}).keys())
        new_paths = set(new_spec.get("paths", {}).keys())
        
        # Новые эндпоинты
        for path in new_paths - old_paths:
            changes.append({
                "type": "new_endpoint",
                "path": path,
                "severity": "info",
                "timestamp": datetime.now().isoformat(),
                "description": f"New endpoint added: {path}"
            })
        
        # Удаленные эндпоинты
        for path in old_paths - new_paths:
            changes.append({
                "type": "removed_endpoint",
                "path": path,
                "severity": "breaking",
                "timestamp": datetime.now().isoformat(),
                "description": f"Endpoint removed: {path}"
            })
        
        # Изменения в существующих эндпоинтах
        for path in old_paths & new_paths:
            endpoint_changes = self._detect_endpoint_changes(
                old_spec["paths"][path],
                new_spec["paths"][path],
                path
            )
            changes.extend(endpoint_changes)
        
        # Изменения в схемах
        schema_changes = self._detect_schema_changes(
            old_spec.get("components", {}).get("schemas", {}),
            new_spec.get("components", {}).get("schemas", {}),
        )
        changes.extend(schema_changes)
        
        return changes
    
    def _detect_endpoint_changes(self, old_endpoint: Dict[str, Any], new_endpoint: Dict[str, Any], path: str) -> List[Dict[str, Any]]:
        """Детекция изменений в эндпоинте"""
        changes = []
        
        # Проверяем изменения в методах
        old_methods = set(old_endpoint.keys())
        new_methods = set(new_endpoint.keys())
        
        # Новые методы
        for method in new_methods - old_methods:
            changes.append({
                "type": "new_method",
                "path": path,
                "method": method.upper(),
                "severity": "info",
                "timestamp": datetime.now().isoformat(),
                "description": f"New method {method.upper()} added to {path}"
            })
        
        # Удаленные методы
        for method in old_methods - new_methods:
            changes.append({
                "type": "removed_method",
                "path": path,
                "method": method.upper(),
                "severity": "breaking",
                "timestamp": datetime.now().isoformat(),
                "description": f"Method {method.upper()} removed from {path}"
            })
        
        # Изменения в существующих методах
        for method in old_methods & new_methods:
            method_changes = self._detect_method_changes(
                old_endpoint[method],
                new_endpoint[method],
                path,
                method
            )
            changes.extend(method_changes)
        
        return changes
    
    def _detect_method_changes(self, old_method: Dict[str, Any], new_method: Dict[str, Any], path: str, method: str) -> List[Dict[str, Any]]:
        """Детекция изменений в методе"""
        changes = []
        
        # Проверяем изменения в параметрах
        old_params = {p["name"]: p for p in old_method.get("parameters", [])}
        new_params = {p["name"]: p for p in new_method.get("parameters", [])}
        
        # Новые параметры
        for param_name in new_params - old_params:
            param = new_params[param_name]
            severity = "info" if param.get("required", False) else "warning"
            changes.append({
                "type": "new_parameter",
                "path": path,
                "method": method.upper(),
                "parameter": param_name,
                "severity": severity,
                "timestamp": datetime.now().isoformat(),
                "description": f"New parameter {param_name} added to {method.upper()} {path}"
            })
        
        # Удаленные параметры
        for param_name in old_params - new_params:
            changes.append({
                "type": "removed_parameter",
                "path": path,
                "method": method.upper(),
                "parameter": param_name,
                "severity": "breaking",
                "timestamp": datetime.now().isoformat(),
                "description": f"Parameter {param_name} removed from {method.upper()} {path}"
            })
        
        # Изменения в существующих параметрах
        for param_name in old_params & new_params:
            param_changes = self._detect_parameter_changes(
                old_params[param_name],
                new_params[param_name],
                path,
                method,
                param_name
            )
            changes.extend(param_changes)
        
        # Проверяем изменения в кодах ответов
        old_responses = set(old_method.get("responses", {}).keys())
        new_responses = set(new_method.get("responses", {}).keys())
        
        # Новые коды ответов
        for code in new_responses - old_responses:
            changes.append({
                "type": "new_response_code",
                "path": path,
                "method": method.upper(),
                "code": code,
                "severity": "info",
                "timestamp": datetime.now().isoformat(),
                "description": f"New response code {code} added to {method.upper()} {path}"
            })
        
        # Удаленные коды ответов
        for code in old_responses - new_responses:
            changes.append({
                "type": "removed_response_code",
                "path": path,
                "method": method.upper(),
                "code": code,
                "severity": "breaking",
                "timestamp": datetime.now().isoformat(),
                "description": f"Response code {code} removed from {method.upper()} {path}"
            })
        
        return changes
    
    def _detect_parameter_changes(self, old_param: Dict[str, Any], new_param: Dict[str, Any], path: str, method: str, param_name: str) -> List[Dict[str, Any]]:
        """Детекция изменений в параметре"""
        changes = []
        
        # Проверяем изменения в типе
        old_type = old_param.get("schema", {}).get("type")
        new_type = new_param.get("schema", {}).get("type")
        
        if old_type != new_type:
            changes.append({
                "type": "parameter_type_changed",
                "path": path,
                "method": method.upper(),
                "parameter": param_name,
                "old_type": old_type,
                "new_type": new_type,
                "severity": "breaking",
                "timestamp": datetime.now().isoformat(),
                "description": f"Parameter {param_name} type changed from {old_type} to {new_type} in {method.upper()} {path}"
            })
        
        # Проверяем изменения в обязательности
        old_required = old_param.get("required", False)
        new_required = new_param.get("required", False)
        
        if old_required != new_required:
            severity = "breaking" if new_required else "warning"
            changes.append({
                "type": "parameter_required_changed",
                "path": path,
                "method": method.upper(),
                "parameter": param_name,
                "old_required": old_required,
                "new_required": new_required,
                "severity": severity,
                "timestamp": datetime.now().isoformat(),
                "description": f"Parameter {param_name} required status changed from {old_required} to {new_required} in {method.upper()} {path}"
            })
        
        return changes
    
    def _detect_schema_changes(self, old_schemas: Dict[str, Any], new_schemas: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Детекция изменений в схемах"""
        changes = []
        
        # Проверяем изменения в схемах
        old_schema_names = set(old_schemas.keys())
        new_schema_names = set(new_schemas.keys())
        
        # Новые схемы
        for schema_name in new_schema_names - old_schema_names:
            changes.append({
                "type": "new_schema",
                "schema": schema_name,
                "severity": "info",
                "timestamp": datetime.now().isoformat(),
                "description": f"New schema added: {schema_name}"
            })
        
        # Удаленные схемы
        for schema_name in old_schema_names - new_schema_names:
            changes.append({
                "type": "removed_schema",
                "schema": schema_name,
                "severity": "breaking",
                "timestamp": datetime.now().isoformat(),
                "description": f"Schema removed: {schema_name}"
            })
        
        # Изменения в существующих схемах
        for schema_name in old_schema_names & new_schema_names:
            schema_changes = self._detect_schema_property_changes(
                old_schemas[schema_name],
                new_schemas[schema_name],
                schema_name
            )
            changes.extend(schema_changes)
        
        return changes
    
    def _detect_schema_property_changes(self, old_schema: Dict[str, Any], new_schema: Dict[str, Any], schema_name: str) -> List[Dict[str, Any]]:
        """Детекция изменений в свойствах схемы"""
        changes = []
        
        # Проверяем изменения в свойствах
        old_properties = old_schema.get("properties", {})
        new_properties = new_schema.get("properties", {})
        
        old_prop_names = set(old_properties.keys())
        new_prop_names = set(new_properties.keys())
        
        # Новые свойства
        for prop_name in new_prop_names - old_prop_names:
            prop = new_properties[prop_name]
            severity = "info" if prop_name not in old_schema.get("required", []) else "warning"
            changes.append({
                "type": "new_schema_property",
                "schema": schema_name,
                "property": prop_name,
                "severity": severity,
                "timestamp": datetime.now().isoformat(),
                "description": f"New property {prop_name} added to schema {schema_name}"
            })
        
        # Удаленные свойства
        for prop_name in old_prop_names - new_prop_names:
            changes.append({
                "type": "removed_schema_property",
                "schema": schema_name,
                "property": prop_name,
                "severity": "breaking",
                "timestamp": datetime.now().isoformat(),
                "description": f"Property {prop_name} removed from schema {schema_name}"
            })
        
        # Изменения в существующих свойствах
        for prop_name in old_prop_names & new_prop_names:
            prop_changes = self._detect_property_changes(
                old_properties[prop_name],
                new_properties[prop_name],
                schema_name,
                prop_name
            )
            changes.extend(prop_changes)
        
        return changes
    
    def _detect_property_changes(self, old_prop: Dict[str, Any], new_prop: Dict[str, Any], schema_name: str, prop_name: str) -> List[Dict[str, Any]]:
        """Детекция изменений в свойстве"""
        changes = []
        
        # Проверяем изменения в типе
        old_type = old_prop.get("type")
        new_type = new_prop.get("type")
        
        if old_type != new_type:
            changes.append({
                "type": "property_type_changed",
                "schema": schema_name,
                "property": prop_name,
                "old_type": old_type,
                "new_type": new_type,
                "severity": "breaking",
                "timestamp": datetime.now().isoformat(),
                "description": f"Property {prop_name} type changed from {old_type} to {new_type} in schema {schema_name}"
            })
        
        # Проверяем изменения в enum
        old_enum = old_prop.get("enum")
        new_enum = new_prop.get("enum")
        
        if old_enum != new_enum:
            if old_enum and new_enum:
                # Проверяем, что новые значения добавляются (не удаляются)
                if set(new_enum).issuperset(set(old_enum)):
                    severity = "info"
                    description = f"New enum values added to property {prop_name} in schema {schema_name}"
                else:
                    severity = "breaking"
                    description = f"Enum values changed for property {prop_name} in schema {schema_name}"
            else:
                severity = "breaking"
                description = f"Enum constraint changed for property {prop_name} in schema {schema_name}"
            
            changes.append({
                "type": "property_enum_changed",
                "schema": schema_name,
                "property": prop_name,
                "old_enum": old_enum,
                "new_enum": new_enum,
                "severity": severity,
                "timestamp": datetime.now().isoformat(),
                "description": description
            })
        
        return changes
    
    def _report_changes(self, changes: List[Dict[str, Any]]):
        """Отчет об изменениях"""
        logger.info(f"Detected {len(changes)} API changes")
        
        for change in changes:
            severity = change["severity"]
            change_type = change["type"]
            description = change["description"]
            
            if severity == "breaking":
                logger.error(f"[BREAKING] {change_type}: {description}")
            elif severity == "warning":
                logger.warning(f"[WARNING] {change_type}: {description}")
            else:
                logger.info(f"[INFO] {change_type}: {description}")
    
    def generate_change_report(self, output_file: str = "api_changes_report.json"):
        """Генерация отчета об изменениях"""
        try:
            report = {
                "timestamp": datetime.now().isoformat(),
                "total_changes": len(self.change_log),
                "breaking_changes": len([c for c in self.change_log if c["severity"] == "breaking"]),
                "warning_changes": len([c for c in self.change_log if c["severity"] == "warning"]),
                "info_changes": len([c for c in self.change_log if c["severity"] == "info"]),
                "changes": self.change_log
            }
            
            with open(output_file, "w") as f:
                json.dump(report, f, indent=2)
            
            logger.info(f"Change report generated: {output_file}")
            
        except Exception as e:
            logger.error(f"Error generating change report: {e}")
    
    def check_backward_compatibility(self) -> bool:
        """Проверка обратной совместимости"""
        breaking_changes = [c for c in self.change_log if c["severity"] == "breaking"]
        
        if breaking_changes:
            logger.error(f"Found {len(breaking_changes)} breaking changes:")
            for change in breaking_changes:
                logger.error(f"  - {change['description']}")
            return False
        
        return True

def main():
    """Основная функция для запуска мониторинга"""
    import argparse
    
    parser = argparse.ArgumentParser(description="API Change Monitor")
    parser.add_argument("--base-url", default="http://localhost:8000", help="Base URL of the API")
    parser.add_argument("--spec-file", default="openapi.yaml", help="OpenAPI specification file")
    parser.add_argument("--use-file", action="store_true", help="Use local file instead of API")
    parser.add_argument("--output", default="api_changes_report.json", help="Output file for change report")
    
    args = parser.parse_args()
    
    # Настройка логирования
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Создание монитора
    monitor = APIChangeMonitor(args.base_url, args.spec_file)
    
    # Проверка изменений
    changes = monitor.check_for_changes(use_file=args.use_file)
    
    if changes:
        # Генерация отчета
        monitor.generate_change_report(args.output)
        
        # Проверка обратной совместимости
        if not monitor.check_backward_compatibility():
            logger.error("API changes break backward compatibility!")
            return 1
        else:
            logger.info("API changes are backward compatible")
    else:
        logger.info("No API changes detected")
    
    return 0

if __name__ == "__main__":
    exit(main())