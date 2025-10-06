# Contributing to Samokoder

First off, thank you for considering contributing to Samokoder! 🎉

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct:
- Be respectful and inclusive
- Welcome newcomers and help them get started
- Focus on constructive criticism
- Respect differing viewpoints

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues. When creating a bug report, include:

- **Clear title and description**
- **Steps to reproduce**
- **Expected vs actual behavior**
- **Environment details** (OS, Python version, etc.)
- **Logs and error messages**

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. Include:

- **Use case** - Why is this needed?
- **Proposed solution** - How should it work?
- **Alternatives** - What other solutions did you consider?

### Pull Requests

1. **Fork the repo** and create your branch from `develop`
2. **Follow our style**:
   - Python: Run `ruff format` and `ruff check`
   - TypeScript: Run `npm run lint` in frontend/
   - Commit messages: Use conventional commits
3. **Add tests** for new functionality
4. **Update documentation** if needed
5. **Ensure CI passes** before submitting

## Development Setup

### Prerequisites

- Python 3.12+
- Node.js 20+
- Docker & Docker Compose
- PostgreSQL 16+ (or use Docker)
- Redis 7+ (or use Docker)

### Local Development

1. **Clone and install**:
```bash
git clone https://github.com/your-org/samokoder.git
cd samokoder
pip install poetry
poetry install
cd frontend && npm install
```

2. **Set up environment**:
```bash
cp .env.example .env
# Edit .env with your values
```

3. **Start services**:
```bash
# Start databases
docker-compose up -d db redis

# Run migrations
poetry run alembic upgrade head

# Start backend
poetry run uvicorn api.main:app --reload

# Start frontend (new terminal)
cd frontend && npm run dev
```

### Running Tests

```bash
# Backend tests
poetry run pytest

# Frontend tests  
cd frontend && npm test

# E2E tests
poetry run pytest -m e2e

# Security scan
poetry run bandit -r core/ api/
poetry run safety check
```

## Project Structure

```
samokoder/
├── api/           # REST API endpoints
├── core/          # Business logic
│   ├── agents/    # AI agents
│   ├── llm/       # LLM integrations
│   └── db/        # Database models
├── frontend/      # React app
├── tests/         # Test suite
├── docs/          # Documentation
└── ops/           # Operations scripts
```

## Style Guide

### Python

- Follow PEP 8
- Use type hints
- Max line length: 120
- Docstrings for public functions

### TypeScript

- Use functional components
- Prefer hooks over classes
- Use strict mode
- Document complex logic

### Commits

We use conventional commits:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation
- `style:` Formatting
- `refactor:` Code restructuring
- `test:` Tests
- `chore:` Maintenance

Example: `feat: add parallel LLM execution for code generation`

## Review Process

1. **Automated checks** must pass
2. **Code review** by at least one maintainer
3. **Tests** must maintain 85%+ coverage
4. **Documentation** must be updated

## Release Process

We use semantic versioning (MAJOR.MINOR.PATCH):

1. Features merged to `develop`
2. Release branch created from `develop`
3. Testing and fixes
4. Merge to `main` and tag
5. Deploy to production

## Getting Help

- 💬 [Discord](#) - Real-time chat
- 📧 dev@samokoder.com - Email support
- 📚 [Docs](docs/) - Technical documentation
- 🐛 [Issues](https://github.com/your-org/samokoder/issues) - Bug reports

## Recognition

Contributors are recognized in:
- CHANGELOG.md
- GitHub contributors page
- Annual contributor spotlight

Thank you for making Samokoder better! 🚀