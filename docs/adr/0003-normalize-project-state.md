# ADR 0003: Normalize ProjectState Storage

**Status:** Proposed  
**Date:** 2025-10-06

## Context

Currently, `ProjectState` stores the entire project state (iterations, steps, tasks, files) in a single JSONB column. This leads to:

1. **Performance issues**: Queries become slow with large JSONB (100+ KB)
2. **Memory overhead**: Loading entire state for minor updates
3. **Lack of indexing**: Cannot efficiently query specific iterations/tasks
4. **Concurrency issues**: Last-write-wins for entire state

## Decision

Normalize the ProjectState into separate tables:

```sql
-- Current (denormalized)
CREATE TABLE project_states (
    id SERIAL PRIMARY KEY,
    project_id UUID REFERENCES projects(id),
    data JSONB,  -- Contains everything
    step_index INT
);

-- Proposed (normalized)
CREATE TABLE project_states (
    id SERIAL PRIMARY KEY,
    project_id UUID REFERENCES projects(id),
    current_step_index INT,
    status VARCHAR(50)
);

CREATE TABLE iterations (
    id SERIAL PRIMARY KEY,
    project_state_id INT REFERENCES project_states(id),
    description TEXT,
    status VARCHAR(50),
    order_index INT
);

CREATE TABLE steps (
    id SERIAL PRIMARY KEY,
    iteration_id INT REFERENCES iterations(id),
    type VARCHAR(50),
    content JSONB,
    status VARCHAR(50),
    order_index INT
);

CREATE TABLE tasks (
    id SERIAL PRIMARY KEY,
    step_id INT REFERENCES steps(id),
    description TEXT,
    status VARCHAR(50),
    assigned_agent VARCHAR(100)
);
```

## Consequences

### Positive
- **50-70% query performance improvement** for large projects
- **Granular updates** without loading entire state
- **Better concurrency** with row-level locks
- **Indexing capabilities** on status, type fields
- **Audit trail** with proper foreign keys

### Negative
- **Migration complexity** for existing data
- **More complex queries** (joins required)
- **Initial development time** (~1-2 weeks)

## Implementation Plan

1. Create new tables with migrations
2. Add repository layer for normalized access
3. Parallel-run both systems for validation
4. Migrate existing data in batches
5. Switch over and deprecate JSONB column