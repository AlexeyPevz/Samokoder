# ADR 0002: Background Worker for Agent Execution

**Status:** Proposed

## Context

The current architecture runs the entire AI agent orchestration (`Orchestrator.run()`) as a long-running asynchronous task within the FastAPI web server process, initiated by a WebSocket connection. This has several critical drawbacks:

1.  **Lack of Robustness:** If the web server process crashes, is restarted for a deployment, or scales down, the agent's execution is abruptly terminated, and all progress is lost. This leads to a frustrating and unreliable user experience.
2.  **Poor Scalability:** The number of concurrent agent sessions is limited by the resources and stability of a single web server instance. It's difficult to scale the compute-intensive agent work independently of the web-serving layer.
3.  **Resource Contention:** A CPU- or memory-intensive agent can degrade the performance and responsiveness of the entire API server, affecting all users.

## Decision

We will decouple agent execution from the web server process by introducing a distributed task queue system. We propose using **ARQ (Asynchronous Redis Queue)** due to its simplicity, high performance, and the fact that Redis is already part of our stack.

1.  When a user starts a generation session, the API endpoint will no longer call `Orchestrator.run()` directly. Instead, it will enqueue a new task (e.g., `run_generation_task(project_id, user_id)`) into an ARQ queue in Redis.
2.  One or more separate, dedicated **worker processes** will listen for tasks on this queue.
3.  When a worker picks up a task, it will instantiate the `Orchestrator` and run the generation process, completely independent of the web server.
4.  Communication back to the user (UI updates) will be handled by the worker process, either by publishing messages to a Redis Pub/Sub channel that the web server listens to and forwards to the correct WebSocket, or by having the worker connect to a dedicated WebSocket proxy.

## Consequences

### Positive

- **Reliability:** Agent tasks are persistent. If a worker or web server crashes, the task remains in the queue and can be retried or resumed, preventing data loss.
- **Scalability:** The web server and agent workers can be scaled independently. We can add more workers to handle more concurrent generation tasks without affecting the API's performance.
- **Resource Isolation:** The API remains fast and responsive, as the heavy lifting is done in separate processes.
- **Improved Observability:** It becomes easier to monitor queue lengths, task execution times, and failure rates as separate metrics.

### Negative

- **Increased Architectural Complexity:** Introduces new components (task queue, worker processes, Pub/Sub channel) that need to be managed, deployed, and monitored.
- **State Management:** Sharing state (like the UI object) between the web server and the worker becomes more complex and requires an intermediary like Redis.
- **Local Development:** The local development setup becomes slightly more complex, as it requires running the ARQ worker process in addition to the web server and database.
