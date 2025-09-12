#!/usr/bin/env python3
"""Упрощенные тесты для Projects API"""

import pytest
from backend.api.projects import router


class TestProjectsAPISimple:
    """Упрощенные тесты для Projects API модуля"""
    
    def test_router_exists(self):
        """Тест существования роутера"""
        assert router is not None
        assert hasattr(router, 'routes')
        assert len(router.routes) > 0
    
    def test_router_endpoints(self):
        """Тест наличия основных эндпоинтов"""
        endpoint_paths = [route.path for route in router.routes]
        
        assert "/" in endpoint_paths
        assert "/{project_id}" in endpoint_paths
        assert "/{project_id}/files" in endpoint_paths
        assert "/{project_id}/chat" in endpoint_paths
    
    def test_create_endpoint(self):
        """Тест эндпоинта создания"""
        for route in router.routes:
            if route.path == "/" and "POST" in route.methods:
                assert "POST" in route.methods
                return
        assert False, "Create endpoint not found"
    
    def test_list_endpoint(self):
        """Тест эндпоинта списка"""
        for route in router.routes:
            if route.path == "/" and "GET" in route.methods:
                assert "GET" in route.methods
                return
        assert False, "List endpoint not found"
    
    def test_get_endpoint(self):
        """Тест эндпоинта получения"""
        for route in router.routes:
            if route.path == "/{project_id}" and "GET" in route.methods:
                assert "GET" in route.methods
                return
        assert False, "Get endpoint not found"
    
    def test_update_endpoint(self):
        """Тест эндпоинта обновления"""
        for route in router.routes:
            if route.path == "/{project_id}" and "PUT" in route.methods:
                assert "PUT" in route.methods
                return
        assert False, "Update endpoint not found"
    
    def test_delete_endpoint(self):
        """Тест эндпоинта удаления"""
        for route in router.routes:
            if route.path == "/{project_id}" and "DELETE" in route.methods:
                assert "DELETE" in route.methods
                return
        assert False, "Delete endpoint not found"
    
    def test_import_structure(self):
        """Тест импортов"""
        from backend.api.projects import router
        assert router is not None
    
    def test_router_config(self):
        """Тест конфигурации роутера"""
        assert hasattr(router, 'prefix')
        assert hasattr(router, 'tags')
        assert hasattr(router, 'dependencies')
    
    def test_route_methods(self):
        """Тест методов маршрутов"""
        for route in router.routes:
            assert hasattr(route, 'methods')
            assert len(route.methods) > 0
            for method in route.methods:
                assert method in ["GET", "POST", "PUT", "DELETE", "PATCH"]
    
    def test_crud_completeness(self):
        """Тест полноты CRUD операций"""
        operations = {"create": False, "read": False, "update": False, "delete": False, "list": False}
        
        for route in router.routes:
            if route.path == "/" and "POST" in route.methods:
                operations["create"] = True
            elif route.path == "/" and "GET" in route.methods:
                operations["list"] = True
            elif route.path == "/{project_id}" and "GET" in route.methods:
                operations["read"] = True
            elif route.path == "/{project_id}" and "PUT" in route.methods:
                operations["update"] = True
            elif route.path == "/{project_id}" and "DELETE" in route.methods:
                operations["delete"] = True
        
        for operation, present in operations.items():
            assert present, f"Missing {operation} operation"