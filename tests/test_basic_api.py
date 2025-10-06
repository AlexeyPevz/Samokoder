import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from samokoder.api.main import app

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from samokoder.api.main import app

def test_health_check(client):
    """Test basic health check endpoint"""
    with client as c:
        response = c.get("/health")
        assert response.status_code == 200
        assert "status" in response.json()

def test_root_endpoint(client):
    """Test root endpoint"""
    with client as c:
        response = c.get("/")
        assert response.status_code == 200
        assert "message" in response.json()

def test_cors_middleware(client):
    """Test CORS middleware is properly configured"""
    with client as c:
        response = c.options("/api/v1/projects", headers={"Origin": "http://localhost:3000", "Access-Control-Request-Method": "GET"})
        assert response.status_code == 200
        assert "access-control-allow-origin" in response.headers
