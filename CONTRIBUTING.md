# Contributing to Samokoder

Спасибо за ваш интерес к проекту Samokoder! Мы приветствуем вклад от сообщества.

## 📋 Содержание

- [Code of Conduct](#code-of-conduct)
- [Как начать](#как-начать)
- [Процесс разработки](#процесс-разработки)
- [Требования к PR](#требования-к-pr)
- [Style Guide](#style-guide)
- [Тестирование](#тестирование)
- [Документация](#документация)

---

## Code of Conduct

Мы следуем принципам уважения и профессионализма. Будьте вежливы, конструктивны и помогайте другим участникам.

---

## Как начать

### 1. Fork и Clone

```bash
# Fork репозитория через GitHub UI
# Затем clone вашего fork:
git clone https://github.com/YOUR-USERNAME/samokoder.git
cd samokoder
```

### 2. Настройка окружения

#### Backend

```bash
# Установите Python 3.12+
curl -sSL https://install.python-poetry.org | python3 -

# Установите зависимости
poetry install

# Активируйте окружение
poetry shell

# Установите pre-commit hooks
poetry run pre-commit install
```

#### Frontend

```bash
cd frontend
npm install
```

#### Базы данных

```bash
# Запустите PostgreSQL и Redis через Docker
docker-compose up -d db redis

# Примените миграции
poetry run alembic upgrade head
```

### 3. Создайте feature branch

```bash
git checkout -b feature/your-feature-name
# или
git checkout -b fix/bug-description
```

---

## Процесс разработки

### Типы изменений

- **feat**: Новая функциональность
- **fix**: Исправление бага
- **docs**: Изменения в документации
- **style**: Форматирование кода (без изменения логики)
- **refactor**: Рефакторинг кода
- **test**: Добавление/исправление тестов
- **chore**: Обновление зависимостей, конфигурации

### Workflow

1. **Создайте issue** (если ещё нет) описывая проблему или feature
2. **Обсудите** в issue перед большими изменениями
3. **Разработайте** в feature branch
4. **Тестируйте** локально
5. **Commit** с понятными сообщениями
6. **Push** в ваш fork
7. **Создайте PR** с описанием изменений

---

## Требования к PR

### Checklist

Перед созданием PR убедитесь что:

- [ ] **Тесты проходят**: `pytest tests/`
- [ ] **Линтеры проходят**: `ruff check .` и `ruff format .`
- [ ] **Coverage не уменьшается**: минимум 80%
- [ ] **Pre-commit hooks пройдены**: `pre-commit run --all-files`
- [ ] **Документация обновлена** (если нужно)
- [ ] **CHANGELOG.md обновлён** (для значительных изменений)
- [ ] **Commit messages осмысленные** (не "fix", "wip", "asdf")

### Формат PR

**Заголовок:**
```
<type>: <краткое описание>

Примеры:
feat: Add async LLM parallel execution
fix: Prevent path traversal in workspace endpoints
docs: Update architecture documentation
```

**Описание:**

```markdown
## Summary
Краткое описание изменений (1-3 предложения).

## Changes
- Изменение 1
- Изменение 2
- Изменение 3

## Testing
Как тестировалось:
- [ ] Unit tests
- [ ] Integration tests
- [ ] Manual testing

## Breaking Changes
(если есть)
- Описание несовместимых изменений
```

---

## Style Guide

### Python

**Используем:**
- **Ruff** для линтинга и форматирования
- **Type hints** обязательно для публичных функций
- **Docstrings** для всех публичных методов (Google style)
- **PEP 8** через Ruff
- **Async/await** для I/O операций

**Пример:**

```python
from typing import Optional
import logging

logger = logging.getLogger(__name__)


async def create_project(
    name: str,
    description: Optional[str] = None,
) -> Project:
    """
    Create a new project.
    
    Args:
        name: Project name
        description: Optional project description
        
    Returns:
        Created Project instance
        
    Raises:
        ValueError: If name is empty
    """
    if not name:
        raise ValueError("Project name is required")
    
    logger.info(f"Creating project: {name}")
    # ... implementation ...
```

### TypeScript/React

**Используем:**
- **ESLint + Prettier**
- **Functional components + hooks**
- **TypeScript strict mode**
- **Named exports** (не default exports)

**Пример:**

```typescript
import { FC, useState } from 'react'
import { Button } from '@/components/ui/button'

interface Props {
  projectId: string
  onComplete: () => void
}

export const ProjectCard: FC<Props> = ({ projectId, onComplete }) => {
  const [loading, setLoading] = useState(false)
  
  // ... implementation ...
}
```

### Naming Conventions

- **Python**: `snake_case` для функций, переменных; `PascalCase` для классов
- **TypeScript**: `camelCase` для переменных, функций; `PascalCase` для компонентов, типов
- **Константы**: `UPPER_SNAKE_CASE`
- **Private methods**: `_leading_underscore`

---

## Тестирование

### Запуск тестов

```bash
# Все тесты
pytest

# С coverage
pytest --cov=core --cov=api --cov-report=html

# Конкретный файл
pytest tests/agents/test_orchestrator.py -v

# Пропустить slow тесты
pytest -m "not slow"
```

### Написание тестов

**Структура:**

```python
# tests/agents/test_orchestrator.py

import pytest
from samokoder.core.agents.orchestrator import Orchestrator


class TestOrchestrator:
    """Tests for Orchestrator agent."""
    
    @pytest.fixture
    def orchestrator(self):
        """Create Orchestrator instance."""
        return Orchestrator(...)
    
    async def test_run_success(self, orchestrator):
        """Test successful orchestrator run."""
        result = await orchestrator.run()
        assert result is True
    
    async def test_run_with_error(self, orchestrator):
        """Test orchestrator handles errors gracefully."""
        # ... test error handling ...
```

**Типы тестов:**

- **Unit tests**: Изолированные тесты компонентов
- **Integration tests**: Тесты взаимодействия модулей
- **Regression tests**: Тесты критичных user flows
- **Contract tests**: Проверка API spec соответствия

---

## Документация

### Что документировать

- **Новые функции**: Обновить README, docs/, docstrings
- **API изменения**: Обновить `openapi.yaml`
- **Архитектурные решения**: Создать ADR в `docs/adr/`
- **Breaking changes**: Добавить в CHANGELOG.md с migration guide

### ADR (Architecture Decision Records)

Для значительных архитектурных решений:

```markdown
# ADR-XXX: Название решения

**Status**: Proposed / Accepted / Deprecated
**Date**: YYYY-MM-DD

## Context
Описание проблемы и контекста.

## Decision
Что было решено.

## Consequences
Последствия (положительные и отрицательные).
```

---

## Процесс Review

1. **CI проверки**: Должны быть зелёными
2. **Code review**: От минимум 1 мейнтейнера
3. **Обсуждение**: Отвечайте на комментарии
4. **Исправления**: Делайте fixup commits, потом squash
5. **Merge**: После approve мейнтейнер смержит PR

---

## Вопросы и помощь

- **GitHub Issues**: Вопросы, баги, feature requests
- **Discussions**: Общие обсуждения
- **Email**: support@samokoder.com

---

## Лицензия

Внося вклад, вы соглашаетесь что ваш код будет под лицензией проекта (FSL-1.1-MIT).

---

Спасибо за ваш вклад! 🚀
