# ---- Build Stage ----
# This stage builds the application and installs dependencies
FROM python:3.12-slim as builder

WORKDIR /app

# Install poetry and configure it to create venv in the project directory
RUN pip install --no-cache-dir --upgrade pip==24.2 && \
    pip install --no-cache-dir poetry==1.8.3
RUN poetry config virtualenvs.in-project true

# Copy dependency files (use existing lock file instead of generating it)
COPY pyproject.toml poetry.lock ./

# Install dependencies without dev packages and without installing the project itself
# This will create a .venv folder in /app
RUN poetry install --without dev --no-root --no-interaction --no-ansi

# Copy only necessary application source code (excluding tests, docs, etc.)
COPY core/ ./core/
COPY api/ ./api/
COPY worker/ ./worker/
COPY alembic/ ./alembic/
COPY alembic.ini ./
COPY __init__.py ./


# ---- Final Stage ----
# This stage creates the final, slim production image
FROM python:3.12-slim

WORKDIR /app

# Create a non-root user
RUN groupadd -r appuser && useradd --no-log-init -r -g appuser appuser

# Copy only the virtual environment from the builder stage
COPY --from=builder --chown=appuser:appuser /app/.venv ./.venv

# Copy only the necessary application source code from the builder stage
COPY --from=builder --chown=appuser:appuser /app/core ./core
COPY --from=builder --chown=appuser:appuser /app/api ./api
COPY --from=builder --chown=appuser:appuser /app/worker ./worker
COPY --from=builder --chown=appuser:appuser /app/alembic ./alembic
COPY --from=builder --chown=appuser:appuser /app/alembic.ini ./
COPY --from=builder --chown=appuser:appuser /app/__init__.py ./

# Create config directory and set permissions
RUN mkdir /app/config && chown appuser:appuser /app/config

# Switch to the non-root user
USER appuser
ENV DATABASE_URL=""

# Activate the virtual environment by adding it to the PATH
ENV PATH="/app/.venv/bin:$PATH"

# Expose the application port
EXPOSE 8000
