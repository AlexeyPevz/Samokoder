# ---- Build Stage ----
# This stage builds the application and installs dependencies
FROM python:3.12 as builder

WORKDIR /app

# Install poetry and configure it to create venv in the project directory
RUN pip install --upgrade pip && pip install poetry
RUN poetry config virtualenvs.in-project true

# Copy dependency configuration and install
COPY pyproject.toml ./
# This will create a .venv folder in /app
RUN poetry lock && poetry install --without dev --no-root

# Copy the entire application source code
COPY . .


# ---- Final Stage ----
# This stage creates the final, slim production image
FROM python:3.12-slim

WORKDIR /app

# Create a non-root user
RUN groupadd -r appuser && useradd --no-log-init -r -g appuser appuser

# Copy the virtual environment from the builder stage
COPY --from=builder --chown=appuser:appuser /app/.venv ./.venv

# Copy the entire application source code from the builder stage
COPY --from=builder --chown=appuser:appuser /app/ /app/

# Create config directory and set permissions
RUN mkdir /app/config && chown appuser:appuser /app/config

# Switch to the non-root user
USER appuser
ENV DATABASE_URL=""

# Activate the virtual environment by adding it to the PATH
ENV PATH="/app/.venv/bin:$PATH"

# Security: Run healthcheck as non-root
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import httpx; r = httpx.get('http://localhost:8000/health'); exit(0 if r.status_code == 200 else 1)"

# Expose the application port
EXPOSE 8000

# Security: Set default command to prevent shell access
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
