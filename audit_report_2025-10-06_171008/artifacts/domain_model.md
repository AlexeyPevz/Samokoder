# Доменная Модель Samokoder

**Дата анализа**: 2025-10-06

## Domain Model Overview

```mermaid
classDiagram
    class User {
        +id: int
        +email: string
        +password_hash: string
        +api_keys: JSONB
        +is_admin: boolean
        +created_at: datetime
        +register()
        +authenticate()
        +store_api_key()
    }
    
    class Project {
        +id: UUID
        +user_id: int
        +name: string
        +description: string
        +folder_name: string
        +status: string
        +created_at: datetime
        +start_generation()
        +update_status()
    }
    
    class Branch {
        +id: int
        +project_id: UUID
        +name: string
        +created_at: datetime
    }
    
    class ProjectState {
        +id: int
        +branch_id: int
        +step_index: int
        +data: JSONB
        +created_at: datetime
        +save_iteration()
        +get_current_step()
    }
    
    class File {
        +id: int
        +project_id: UUID
        +path: string
        +content_id: int
        +created_at: datetime
        +save_content()
        +get_content()
    }
    
    class FileContent {
        +id: int
        +content: text
        +created_at: datetime
    }
    
    class LLMRequest {
        +id: int
        +project_id: UUID
        +provider: string
        +model: string
        +prompt: text
        +response: text
        +tokens: int
        +cost: decimal
        +latency_ms: int
        +track_usage()
    }
    
    class Task {
        +id: int
        +project_run_id: int
        +description: string
        +instructions: string
        +status: string
        +execute()
        +update_status()
    }
    
    class Iteration {
        +id: int
        +project_run_id: int
        +description: string
        +user_stories: JSONB
        +status: string
        +run()
        +complete()
    }
    
    class ExecutionLog {
        +id: int
        +project_id: UUID
        +command: string
        +stdout: text
        +stderr: text
        +exit_code: int
        +created_at: datetime
    }
    
    User "1" --> "*" Project : owns
    Project "1" --> "*" Branch : has
    Branch "1" --> "*" ProjectState : contains
    Project "1" --> "*" File : contains
    File "*" --> "1" FileContent : references
    Project "1" --> "*" LLMRequest : generates
    Project "1" --> "*" Task : executes
    Project "1" --> "*" Iteration : runs
    Project "1" --> "*" ExecutionLog : logs
```

## Aggregate Boundaries

### User Aggregate
```mermaid
graph TB
    subgraph "User Aggregate"
        User[User<br/>Root Entity]
        APIKeys[API Keys<br/>Value Object]
        Auth[Authentication<br/>Service]
    end
    
    User --> APIKeys
    User --> Auth
```

**Invariants:**
- Email must be unique
- Password must be hashed with bcrypt
- API keys must be encrypted with Fernet
- JWT tokens expire after configured time

### Project Aggregate
```mermaid
graph TB
    subgraph "Project Aggregate"
        Project[Project<br/>Root Entity]
        Branch[Branch<br/>Entity]
        ProjectState[ProjectState<br/>Entity]
        File[File<br/>Entity]
        FileContent[FileContent<br/>Value Object]
    end
    
    Project --> Branch
    Branch --> ProjectState
    Project --> File
    File --> FileContent
```

**Invariants:**
- Project belongs to one User
- folder_name is auto-generated from name
- Deleting Project cascades to all related entities
- ProjectState is immutable (new step = new record)

### Generation Pipeline Aggregate
```mermaid
graph TB
    subgraph "Generation Pipeline"
        Orchestrator[Orchestrator<br/>Service]
        Iteration[Iteration<br/>Entity]
        Step[Step<br/>Value Object]
        Task[Task<br/>Entity]
        Agent[Agent<br/>Service]
    end
    
    Orchestrator --> Iteration
    Iteration --> Step
    Step --> Task
    Task --> Agent
```

**Invariants:**
- Pipeline executes sequentially
- Parallel agents work on independent files only
- BugHunter activates only on errors
- Maximum 3 retry attempts per error

## Domain Events

### User Context Events
```mermaid
graph LR
    UserRegistered[UserRegistered]
    UserAuthenticated[UserAuthenticated]
    APIKeyStored[APIKeyStored]
    APIKeyRevoked[APIKeyRevoked]
    
    UserRegistered --> UserAuthenticated
    UserAuthenticated --> APIKeyStored
```

### Project Generation Events
```mermaid
graph TB
    ProjectCreated[ProjectCreated]
    GenerationStarted[GenerationStarted]
    SpecificationGenerated[SpecificationGenerated]
    ArchitectureDesigned[ArchitectureDesigned]
    TasksCreated[TasksCreated]
    CodeGenerated[CodeGenerated]
    CommandExecuted[CommandExecuted]
    ErrorDetected[ErrorDetected]
    ErrorFixed[ErrorFixed]
    GenerationCompleted[GenerationCompleted]
    
    ProjectCreated --> GenerationStarted
    GenerationStarted --> SpecificationGenerated
    SpecificationGenerated --> ArchitectureDesigned
    ArchitectureDesigned --> TasksCreated
    TasksCreated --> CodeGenerated
    CodeGenerated --> CommandExecuted
    CommandExecuted -->|Success| GenerationCompleted
    CommandExecuted -->|Error| ErrorDetected
    ErrorDetected --> ErrorFixed
    ErrorFixed --> CommandExecuted
```

## Value Objects

### Specification
```json
{
  "name": "string",
  "description": "string",
  "features": ["string"],
  "tech_stack": {
    "frontend": "string",
    "backend": "string",
    "database": "string"
  },
  "constraints": ["string"]
}
```

### Architecture
```json
{
  "structure": {
    "frontend": {},
    "backend": {},
    "database": {}
  },
  "dependencies": {},
  "deployment": {}
}
```

### ProjectState Data
```json
{
  "iterations": [{
    "description": "string",
    "user_stories": ["string"],
    "status": "pending|in_progress|completed"
  }],
  "steps": [{
    "type": "command|save_file|human_intervention",
    "content": "string",
    "related_files": ["string"]
  }],
  "tasks": [{
    "description": "string",
    "instructions": "string",
    "files": ["string"],
    "status": "pending|in_progress|done"
  }],
  "files": {},
  "epics": []
}
```

## Business Rules

### Authentication & Authorization
1. **User Registration**
   - Email must be unique
   - Password minimum 8 characters
   - Email verification (not implemented)

2. **API Access**
   - All endpoints require JWT except auth
   - Admin endpoints require is_admin=true
   - Rate limiting per endpoint

3. **API Key Management**
   - Users can store encrypted API keys
   - BYOK (Bring Your Own Key) model
   - Keys are provider-specific

### Project Generation
1. **Project Creation**
   - User must be authenticated
   - Project name required
   - Folder name auto-generated
   - Rate limited to 10/day

2. **Generation Pipeline**
   - Sequential execution of agents
   - Parallel execution for independent tasks
   - Automatic retry on failures (max 3)
   - Timeout per step (configurable)

3. **Resource Management**
   - Docker containers auto-cleanup after 24h
   - File size limits (not implemented)
   - Token usage tracking for billing

### Data Management
1. **File Storage**
   - Relative paths only (security)
   - Path traversal prevention
   - Immutable file content (versioning)

2. **State Management**
   - ProjectState is append-only
   - Complete state snapshot per step
   - JSON schema validation (partial)

3. **Audit & Analytics**
   - All LLM requests logged
   - Token usage tracked
   - Cost calculation per request
   - Performance metrics collected

## Anti-Corruption Layers

### LLM Provider ACL
```mermaid
graph LR
    subgraph "Domain"
        Agent[Agent]
        Request[LLM Request]
    end
    
    subgraph "ACL"
        BaseLLM[BaseLLMClient]
        OpenAIAdapter[OpenAI Adapter]
        AnthropicAdapter[Anthropic Adapter]
        GroqAdapter[Groq Adapter]
    end
    
    subgraph "External"
        OpenAI[OpenAI API]
        Anthropic[Anthropic API]
        Groq[Groq API]
    end
    
    Agent --> Request
    Request --> BaseLLM
    BaseLLM --> OpenAIAdapter
    BaseLLM --> AnthropicAdapter
    BaseLLM --> GroqAdapter
    OpenAIAdapter --> OpenAI
    AnthropicAdapter --> Anthropic
    GroqAdapter --> Groq
```

### Docker Execution ACL
```mermaid
graph LR
    subgraph "Domain"
        Executor[Executor Agent]
        Command[Execution Command]
    end
    
    subgraph "ACL"
        ProcessManager[Process Manager]
        DockerClient[Docker Client]
    end
    
    subgraph "External"
        Docker[Docker Engine]
    end
    
    Executor --> Command
    Command --> ProcessManager
    ProcessManager --> DockerClient
    DockerClient --> Docker
```

## Domain Service Interactions

```mermaid
graph TB
    subgraph "Application Services"
        ProjectService[Project Service]
        UserService[User Service]
        GenerationService[Generation Service]
    end
    
    subgraph "Domain Services"
        Orchestrator[Orchestrator]
        StateManager[State Manager]
        SecurityService[Security Service]
    end
    
    subgraph "Infrastructure Services"
        FileService[File Service]
        LLMService[LLM Service]
        DockerService[Docker Service]
    end
    
    ProjectService --> GenerationService
    GenerationService --> Orchestrator
    Orchestrator --> StateManager
    Orchestrator --> LLMService
    Orchestrator --> DockerService
    UserService --> SecurityService
    StateManager --> FileService
```

## Consistency Boundaries

### Strong Consistency
- User registration/authentication
- Project creation/deletion
- Financial transactions (future)

### Eventual Consistency
- Project generation pipeline
- File synchronization
- Analytics aggregation

### Read Models (CQRS Pattern - Future)
- Project listing with filters
- Analytics dashboards
- Usage reports