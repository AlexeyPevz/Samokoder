# ADR 0001: Git-Based Workspace Storage

**Status:** Proposed

## Context

The current implementation of project history stores a complete snapshot of every file for each `ProjectState` directly in the database. While this provides immutability, it leads to severe scalability issues:

1.  **Data Duplication:** A project with 100 files undergoing 200 changes will result in approximately 20,000 file records in the database, most of which are duplicates.
2.  **Performance Degradation:** Creating a new `ProjectState` is a heavy operation, involving cloning hundreds of database rows.
3.  **High Storage Costs:** The database size grows exponentially with user activity, leading to significant and unnecessary storage costs.

## Decision

We will replace the database-backed file versioning system with a system that uses bare Git repositories as the backend for each project's workspace.

- Each `Project` will have a corresponding bare Git repository created on the application server's filesystem (e.g., in a `/data/project_repos/{project_id}.git` directory).
- The `ProjectState` model will no longer have a relationship with `File` models. Instead, it will store a single `commit_hash` string, pointing to a commit in the project's Git repository.
- A new service, `GitWorkspaceManager`, will be created to abstract all interactions with the Git repositories (e.g., creating repos, checking out revisions, committing changes).

## Consequences

### Positive

- **Massive Storage Reduction:** Database storage for project history will be reduced by >99%, as only commit hashes are stored. Git is highly optimized for storing file diffs.
- **Improved Performance:** Creating a new project state becomes a lightweight `git commit` operation, which is significantly faster than cloning hundreds of SQL rows.
- **Robustness:** Leverages an industry-standard, battle-tested tool for file versioning.
- **New Feature Enablement:** Opens the door for future features like viewing diffs between steps, branching/merging development ideas, and easier project exporting.

### Negative

- **New Dependency:** The application environment will require access to a Git executable or a Python Git library (like `pygit2` or `GitPython`).
- **Increased Complexity:** Introduces the need to manage Git repositories on the filesystem, including creation, garbage collection, and ensuring proper access controls.
- **Data Migration:** A migration strategy will be required to convert existing projects from the database-snapshot format to Git repositories.
