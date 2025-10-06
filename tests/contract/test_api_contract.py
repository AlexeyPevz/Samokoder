"""Contract tests for API endpoints against OpenAPI spec."""
import pytest
import yaml
from pathlib import Path
from fastapi.testclient import TestClient
from jsonschema import validate, ValidationError

from api.main import app


class TestAPIContract:
    """Test API responses match OpenAPI specification."""
    
    @pytest.fixture(scope="class")
    def openapi_spec(self):
        """Load OpenAPI specification."""
        spec_path = Path(__file__).parent.parent.parent / "openapi.yaml"
        with open(spec_path) as f:
            return yaml.safe_load(f)
    
    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)
    
    def test_auth_register_contract(self, client, openapi_spec):
        """Test /auth/register matches contract."""
        # Get schema from OpenAPI spec
        register_schema = openapi_spec["paths"]["/v1/auth/register"]["post"]
        request_schema = register_schema["requestBody"]["content"]["application/json"]["schema"]
        response_schema = register_schema["responses"]["201"]["content"]["application/json"]["schema"]
        
        # Valid request
        request_data = {
            "email": "test@example.com",
            "password": "SecurePass123!"
        }
        
        # Validate request matches schema
        try:
            validate(request_data, request_schema)
        except ValidationError as e:
            pytest.fail(f"Request doesn't match schema: {e}")
        
        # Make request
        response = client.post("/v1/auth/register", json=request_data)
        
        # Validate response matches schema
        if response.status_code == 201:
            try:
                validate(response.json(), response_schema)
            except ValidationError as e:
                pytest.fail(f"Response doesn't match schema: {e}")
    
    def test_projects_list_contract(self, client, openapi_spec, auth_headers):
        """Test /projects matches contract."""
        projects_schema = openapi_spec["paths"]["/v1/projects"]["get"]
        response_schema = projects_schema["responses"]["200"]["content"]["application/json"]["schema"]
        
        response = client.get("/v1/projects", headers=auth_headers)
        
        assert response.status_code == 200
        
        try:
            validate(response.json(), response_schema)
        except ValidationError as e:
            pytest.fail(f"Response doesn't match schema: {e}")
    
    @pytest.mark.parametrize("endpoint,method", [
        ("/v1/auth/login", "post"),
        ("/v1/auth/me", "get"),
        ("/v1/projects", "get"),
        ("/v1/projects", "post"),
        ("/v1/keys", "get"),
        ("/v1/models", "get"),
    ])
    def test_endpoint_exists(self, client, openapi_spec, endpoint, method):
        """Test that all documented endpoints exist."""
        # Check endpoint is in spec
        assert endpoint in openapi_spec["paths"], f"{endpoint} not in OpenAPI spec"
        assert method in openapi_spec["paths"][endpoint], f"{method} {endpoint} not in spec"
        
        # Check endpoint exists in app
        response = client.options(endpoint)
        allowed_methods = response.headers.get("allow", "").lower().split(", ")
        assert method in allowed_methods, f"{method} not allowed for {endpoint}"