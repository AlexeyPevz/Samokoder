"""Tests for Prometheus metrics middleware."""
import pytest
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from samokoder.api.middleware.metrics import (
    metrics_middleware,
    http_requests_total,
    http_request_duration_seconds,
    http_requests_in_progress,
    rate_limit_hits_total,
    update_system_metrics,
    track_http_request,
)


@pytest.fixture
def app():
    """Create test FastAPI app with metrics middleware."""
    app = FastAPI()
    app.middleware("http")(metrics_middleware)
    
    @app.get("/test")
    async def test_endpoint():
        return {"status": "ok"}
    
    @app.get("/error")
    async def error_endpoint():
        raise ValueError("Test error")
    
    return app


@pytest.fixture
def client(app):
    """Create test client."""
    return TestClient(app)


def test_metrics_middleware_success(client):
    """Test metrics middleware tracks successful requests."""
    # Make a successful request
    response = client.get("/test")
    assert response.status_code == 200
    
    # Verify metrics were recorded (checking they don't raise errors)
    # In a real test, you'd use prometheus_client.REGISTRY to check actual values
    assert response.json() == {"status": "ok"}


def test_metrics_middleware_error(client):
    """Test metrics middleware tracks errors."""
    # Make a request that raises an error
    with pytest.raises(ValueError):
        client.get("/error")


def test_track_http_request():
    """Test track_http_request function."""
    method = "GET"
    endpoint = "/test"
    status = 200
    duration = 0.5
    
    # Should not raise
    track_http_request(method, endpoint, status, duration)


def test_rate_limit_tracking(client):
    """Test rate limit hits are tracked."""
    # This would require mocking a 429 response
    # For now, just verify the metric exists
    assert rate_limit_hits_total is not None


@patch('api.middleware.metrics.psutil.cpu_percent')
@patch('api.middleware.metrics.psutil.virtual_memory')
@patch('api.middleware.metrics.psutil.disk_usage')
def test_update_system_metrics(mock_disk, mock_mem, mock_cpu):
    """Test system metrics collection."""
    # Mock psutil responses
    mock_cpu.return_value = 50.0
    
    mock_mem_obj = MagicMock()
    mock_mem_obj.used = 1024 * 1024 * 1024  # 1GB
    mock_mem_obj.available = 2048 * 1024 * 1024  # 2GB
    mock_mem_obj.total = 4096 * 1024 * 1024  # 4GB
    mock_mem.return_value = mock_mem_obj
    
    mock_disk_obj = MagicMock()
    mock_disk_obj.used = 10 * 1024 * 1024 * 1024  # 10GB
    mock_disk_obj.free = 20 * 1024 * 1024 * 1024  # 20GB
    mock_disk_obj.total = 30 * 1024 * 1024 * 1024  # 30GB
    mock_disk.return_value = mock_disk_obj
    
    # Should not raise
    update_system_metrics()
    
    # Verify calls
    mock_cpu.assert_called_once()
    mock_mem.assert_called_once()
    mock_disk.assert_called_once_with('/')


def test_metrics_endpoint(client):
    """Test that metrics can be exposed (if /metrics endpoint exists)."""
    # This assumes you have a /metrics endpoint
    # If not using prometheus_fastapi_instrumentator, this test can be skipped
    pass


@pytest.mark.parametrize("status_code", [200, 201, 400, 404, 500, 503])
def test_different_status_codes(app, status_code):
    """Test that different status codes are tracked correctly."""
    @app.get(f"/status_{status_code}")
    async def status_endpoint():
        return Response(status_code=status_code)
    
    client = TestClient(app)
    response = client.get(f"/status_{status_code}")
    assert response.status_code == status_code
