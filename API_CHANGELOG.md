# API Changelog

All notable changes to the Samokoder API will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Path validation for workspace endpoints to prevent directory traversal
- Request size limits (100MB max)
- Web Vitals tracking endpoint `/v1/analytics/vitals`

### Security
- Added HEALTHCHECK to Dockerfile
- Improved path sanitization in workspace endpoints

## [1.0.0] - 2025-10-01

### Added
- Initial API release with `/v1` prefix
- Authentication endpoints (`/v1/auth/*`)
- Project management endpoints (`/v1/projects/*`)
- API key management (`/v1/keys/*`)
- LLM model listing (`/v1/models/*`)
- Workspace file operations (`/v1/workspace/*`)
- Usage tracking (`/v1/usage/*`)
- Analytics endpoints (`/v1/analytics/*`)

### Security
- JWT authentication with token revocation
- Rate limiting on all endpoints
- Encrypted storage for user API keys
- Brute force protection on login

## Breaking Changes Policy

We follow semantic versioning:
- MAJOR version (v2, v3) - Breaking changes
- MINOR version (v1.1, v1.2) - New features, backwards compatible  
- PATCH version (v1.0.1) - Bug fixes

Before any breaking change:
1. New version will be available at `/v2` while `/v1` remains
2. Deprecation notice 3 months in advance
3. Migration guide published
4. `/v1` supported for 6 months after `/v2` release