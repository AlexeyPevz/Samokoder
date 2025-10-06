# Архитектурная Карта Samokoder

**Дата анализа**: 2025-10-06

## High-Level Architecture

```mermaid
graph TB
    subgraph "Client Layer"
        Browser[Web Browser]
        API_Client[API Clients]
    end
    
    subgraph "Application Layer"
        subgraph "Frontend"
            React[React SPA<br/>TypeScript, Vite]
            UI_Components[Radix UI Components]
        end
        
        subgraph "Backend API"
            FastAPI[FastAPI Server]
            Auth[JWT Auth]
            RateLimit[Rate Limiter]
            Metrics[Prometheus Metrics]
        end
    end
    
    subgraph "Business Logic Layer"
        subgraph "Core Domain"
            Orchestrator[Agent Orchestrator]
            Agents[15+ AI Agents]
            StateManager[State Manager]
            LLM_Abstraction[LLM Abstraction Layer]
        end
        
        subgraph "Services"
            ProjectService[Project Service]
            UserService[User Service]
            FileService[File Service]
            SecurityService[Security Service]
        end
    end
    
    subgraph "Infrastructure Layer"
        subgraph "Data Storage"
            PostgreSQL[(PostgreSQL 15)]
            Redis[(Redis 7)]
            FileSystem[File System]
        end
        
        subgraph "External Services"
            OpenAI[OpenAI API]
            Anthropic[Anthropic API]
            Groq[Groq API]
            Docker[Docker Engine]
        end
        
        subgraph "Background Processing"
            ARQ[ARQ Worker]
            JobQueue[Redis Job Queue]
        end
    end
    
    subgraph "Monitoring & Observability"
        Prometheus[Prometheus]
        Grafana[Grafana]
        AlertManager[AlertManager]
    end

    Browser --> React
    API_Client --> FastAPI
    React --> FastAPI
    FastAPI --> Auth
    FastAPI --> RateLimit
    FastAPI --> Metrics
    FastAPI --> ProjectService
    FastAPI --> UserService
    ProjectService --> Orchestrator
    Orchestrator --> Agents
    Agents --> StateManager
    Agents --> LLM_Abstraction
    LLM_Abstraction --> OpenAI
    LLM_Abstraction --> Anthropic
    LLM_Abstraction --> Groq
    Agents --> Docker
    StateManager --> PostgreSQL
    StateManager --> FileSystem
    Auth --> Redis
    RateLimit --> Redis
    ProjectService --> ARQ
    ARQ --> JobQueue
    JobQueue --> Redis
    Metrics --> Prometheus
    Prometheus --> Grafana
    Prometheus --> AlertManager
```

## Component Architecture

### 1. Frontend Architecture

```mermaid
graph LR
    subgraph "React Application"
        Pages[Pages<br/>Dashboard, Projects, etc]
        Components[Reusable Components]
        Hooks[Custom Hooks]
        Services[API Services]
        Context[React Context]
    end
    
    subgraph "State Management"
        ReactQuery[React Query]
        LocalState[Component State]
    end
    
    subgraph "UI Layer"
        RadixUI[Radix UI]
        TailwindCSS[Tailwind CSS]
        Monaco[Monaco Editor]
        XTerm[xterm.js]
    end
    
    Pages --> Components
    Pages --> Hooks
    Hooks --> Services
    Services --> ReactQuery
    Components --> RadixUI
    Components --> TailwindCSS
    Pages --> Monaco
    Pages --> XTerm
    Context --> LocalState
```

### 2. Backend API Architecture

```mermaid
graph TB
    subgraph "API Layer"
        Routers[Routers<br/>auth, projects, keys, etc]
        Middleware[Middleware<br/>CORS, RateLimit, Metrics]
        Dependencies[Dependencies<br/>get_db, get_current_user]
    end
    
    subgraph "Business Logic"
        Services[Services]
        Validators[Pydantic Models]
        Security[Security Layer]
    end
    
    subgraph "Data Access"
        Models[SQLAlchemy Models]
        Repositories[Repositories]
        Database[(PostgreSQL)]
    end
    
    Routers --> Middleware
    Middleware --> Dependencies
    Dependencies --> Services
    Services --> Validators
    Services --> Security
    Services --> Repositories
    Repositories --> Models
    Models --> Database
```

### 3. Agent System Architecture

```mermaid
graph TB
    subgraph "Agent Pipeline"
        Start[User Request]
        Spec[SpecWriter Agent]
        Arch[Architect Agent]
        Tech[TechLead Agent]
        Dev[Developer Agents]
        CodeMonkey[CodeMonkey Agents]
        Exec[Executor Agent]
        Debug[BugHunter Agent]
        Trouble[Troubleshooter Agent]
        End[Completed Project]
    end
    
    subgraph "Support Systems"
        State[State Manager]
        LLM[LLM Clients]
        Docker[Docker Manager]
        Files[File System]
    end
    
    Start --> Spec
    Spec --> Arch
    Arch --> Tech
    Tech --> Dev
    Tech --> CodeMonkey
    Dev --> Exec
    CodeMonkey --> Exec
    Exec -->|Error| Debug
    Debug --> Trouble
    Trouble --> Exec
    Exec -->|Success| End
    
    Spec --> LLM
    Arch --> LLM
    Tech --> LLM
    Dev --> LLM
    CodeMonkey --> LLM
    Debug --> LLM
    Trouble --> LLM
    
    All --> State
    Exec --> Docker
    All --> Files
```

## Data Flow Architecture

### 1. Project Generation Flow

```mermaid
sequenceDiagram
    participant User
    participant Frontend
    participant API
    participant Database
    participant ARQ
    participant Worker
    participant Agents
    participant LLM
    participant Docker
    
    User->>Frontend: Create Project
    Frontend->>API: POST /projects
    API->>Database: Save Project
    API->>ARQ: Enqueue Job
    API-->>Frontend: Project ID
    
    ARQ->>Worker: Pick up Job
    Worker->>Database: Load Project
    Worker->>Agents: Start Orchestration
    
    loop For each Agent
        Agents->>LLM: Generate Content
        LLM-->>Agents: Response
        Agents->>Database: Update State
    end
    
    Agents->>Docker: Execute Code
    Docker-->>Agents: Results
    
    Worker->>Database: Save Final State
    Worker-->>Frontend: WebSocket Update
```

### 2. Authentication Flow

```mermaid
sequenceDiagram
    participant User
    participant Frontend
    participant API
    participant Redis
    participant Database
    
    User->>Frontend: Login
    Frontend->>API: POST /auth/login
    API->>Database: Verify Credentials
    Database-->>API: User Data
    API->>API: Generate JWT
    API->>Redis: Store Session
    API-->>Frontend: JWT Token
    Frontend->>Frontend: Store Token
    
    Note over Frontend,API: Subsequent Requests
    Frontend->>API: Request + JWT
    API->>API: Verify JWT
    API->>Redis: Check Session
    API-->>Frontend: Response
```

## Deployment Architecture

```mermaid
graph TB
    subgraph "External"
        Internet[Internet]
        DNS[DNS]
    end
    
    subgraph "Edge Layer"
        Traefik[Traefik<br/>Reverse Proxy<br/>SSL Termination]
    end
    
    subgraph "Application Containers"
        Frontend_Container[Frontend<br/>nginx + React]
        API_Container[API<br/>uvicorn + FastAPI]
        Worker_Container[Worker<br/>ARQ]
    end
    
    subgraph "Data Containers"
        PostgreSQL_Container[(PostgreSQL)]
        Redis_Container[(Redis)]
    end
    
    subgraph "Monitoring Containers"
        Prometheus_Container[Prometheus]
        Grafana_Container[Grafana]
        AlertManager_Container[AlertManager]
        Exporters[Exporters<br/>postgres, redis, cadvisor]
    end
    
    subgraph "Volumes"
        DB_Volume[postgres_data]
        Redis_Volume[redis_data]
        Workspace_Volume[workspace]
    end
    
    Internet --> DNS
    DNS --> Traefik
    Traefik --> Frontend_Container
    Traefik --> API_Container
    API_Container --> PostgreSQL_Container
    API_Container --> Redis_Container
    Worker_Container --> PostgreSQL_Container
    Worker_Container --> Redis_Container
    PostgreSQL_Container --> DB_Volume
    Redis_Container --> Redis_Volume
    API_Container --> Workspace_Volume
    Worker_Container --> Workspace_Volume
    Exporters --> PostgreSQL_Container
    Exporters --> Redis_Container
    Prometheus_Container --> Exporters
    Grafana_Container --> Prometheus_Container
    AlertManager_Container --> Prometheus_Container
```

## Security Architecture

### Security Layers

1. **Network Security**
   - HTTPS via Traefik
   - CORS configuration
   - Network isolation (Docker networks)

2. **Application Security**
   - JWT Authentication
   - Rate Limiting (SlowAPI + Redis)
   - Input Validation (Pydantic)
   - CSRF Protection (planned)

3. **Data Security**
   - Password Hashing (bcrypt)
   - API Key Encryption (Fernet)
   - Database Encryption at Rest

4. **Infrastructure Security**
   - Docker Security Options
   - Read-only Docker Socket
   - Container Resource Limits
   - Automated Security Scanning (CI/CD)

## Scalability Considerations

### Current Limitations
1. **Single Worker Instance** - bottleneck for concurrent generations
2. **Single Database** - no read replicas
3. **Local File Storage** - not suitable for multi-host
4. **Large JSONB Columns** - performance impact

### Scaling Path
1. **Horizontal Scaling**
   - Multiple Worker instances (ARQ supports)
   - API load balancing
   - PostgreSQL read replicas

2. **Storage Scaling**
   - S3 for file storage
   - Redis Cluster
   - Database partitioning

3. **Performance Optimization**
   - Caching layer
   - CDN for static assets
   - Query optimization

## Technology Stack Summary

### Backend
- **Language**: Python 3.12+
- **Framework**: FastAPI (async)
- **ORM**: SQLAlchemy 2.0 (async)
- **Database**: PostgreSQL 15
- **Cache/Queue**: Redis 7
- **Background Jobs**: ARQ
- **LLM Integration**: OpenAI, Anthropic, Groq

### Frontend
- **Framework**: React 18
- **Language**: TypeScript
- **Build Tool**: Vite
- **UI Library**: Radix UI
- **State Management**: React Query
- **Styling**: Tailwind CSS

### Infrastructure
- **Containerization**: Docker
- **Orchestration**: Docker Compose
- **Reverse Proxy**: Traefik
- **Monitoring**: Prometheus + Grafana
- **CI/CD**: GitHub Actions