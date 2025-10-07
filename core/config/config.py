from enum import Enum
from typing import Dict, Optional, Union
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
import json
import os
from pathlib import Path

# Database Configuration
class DBConfig(BaseModel):
    url: str = Field(default="sqlite+aiosqlite:///pilot.db", validation_alias="DATABASE_URL")
    debug_sql: bool = False

# UI Configuration
class DatabaseConfig(BaseModel):
    url: str = "sqlite+aiosqlite:///pilot.db"
    debug_sql: bool = False


class UIAdapter(str, Enum):
    PLAIN = "plain"
    IPC_CLIENT = "ipc-client"
    VIRTUAL = "virtual"

class UIConfig(BaseModel):
    type: str = "plain"

# IPC Configuration
class LocalIPCConfig(UIConfig):
    type: str = "ipc-client"
    port: int = 8123
    host: str = "localhost"

# Constants for agent names
GET_RELEVANT_FILES_AGENT_NAME = "GetRelevantFiles"
TASK_BREAKDOWN_AGENT_NAME = "TaskBreakdown"
TROUBLESHOOTER_BUG_REPORT = "TroubleshooterBugReport"
PARSE_TASK_AGENT_NAME = "ParseTask"
CHECK_LOGS_AGENT_NAME = "CheckLogs"
CODE_MONKEY_AGENT_NAME = "CodeMonkey"
CODE_REVIEW_AGENT_NAME = "CodeReview"
DESCRIBE_FILES_AGENT_NAME = "DescribeFiles"
FRONTEND_AGENT_NAME = "Frontend"
TROUBLESHOOTER_GET_RUN_COMMAND = "TroubleshooterGetRunCommand"
SPEC_WRITER_AGENT_NAME = "SpecWriter"
TECH_LEAD_EPIC_BREAKDOWN = "TechLeadEpicBreakdown"
TECH_LEAD_PLANNING = "TechLeadPlanning"

# External documentation API
EXTERNAL_DOCUMENTATION_API = "https://docs.samokoder.io/api/"  # Placeholder URL

# Magic words
class MagicWords:
    PROBLEM_IDENTIFIED = "PROBLEM_IDENTIFIED"
    ADD_LOGS = "ADD_LOGS"
    THINKING_LOGS = [
                    "Samokoder is crunching the numbers...",
                    "Samokoder is deep in thought...",
                    "Samokoder is analyzing your request...",
                    "Samokoder is brewing up a solution...",
                    "Samokoder is putting the pieces together...",
                    "Samokoder is working its magic...",
                    "Samokoder is crafting the perfect response...",
                    "Samokoder is decoding your query...",
                    "Samokoder is on the case...",
                    "Samokoder is computing an answer...",
                    "Samokoder is sorting through the data...",
                    "Samokoder is gathering insights...",
                    "Samokoder is making connections...",
                    "Samokoder is tuning the algorithms...",
                    "Samokoder is piecing together the puzzle...",
                    "Samokoder is scanning the possibilities...",
                    "Samokoder is engineering a response...",
                    "Samokoder is building the answer...",
                    "Samokoder is mapping out a solution...",
                    "Samokoder is figuring this out for you...",
                    "Samokoder is thinking hard right now...",
                    "Samokoder is working for you, so relax!",
                    "Samokoder might take some time to figure this out...",    ]

magic_words = MagicWords()

class FileSystemType(str, Enum):
    LOCAL = "local"
    DOCKER = "docker"

class LLMProvider(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GROQ = "groq"
    AZURE = "azure"

class ProviderConfig(BaseModel):
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    connect_timeout: float = 60.0
    read_timeout: float = 20.0
    extra: Dict = Field(default_factory=dict)

class AgentLLMConfig(BaseModel):
    provider: LLMProvider = LLMProvider.OPENAI
    model: str = "gpt-4o-2024-05-13"
    temperature: float = 0.5

class LLMConfig(BaseModel):
    openai: ProviderConfig = Field(default_factory=ProviderConfig)
    anthropic: ProviderConfig = Field(default_factory=ProviderConfig)
    groq: ProviderConfig = Field(default_factory=ProviderConfig)
    azure: ProviderConfig = Field(default_factory=ProviderConfig)

class PromptConfig(BaseModel):
    paths: list[str] = ["core/prompts"]

class LogConfig(BaseModel):
    level: str = "INFO"
    format: str = "%(asctime)s %(levelname)s [%(name)s] %(message)s"
    output: Optional[str] = None

class FileSystemConfig(BaseModel):
    type: str = "local"
    workspace_root: str = "workspace"
    ignore_paths: list = [
        ".git",
        ".samokoder",
        ".idea",
        ".vscode",
        ".next",
        ".DS_Store",
        "__pycache__",
        "site-packages",
        "node_modules",
        "package-lock.json",
        "venv",
        "dist",
        "build",
        "target",
        "*.min.js",
        "*.min.css",
        "*.svg",
        "*.csv",
        "*.log",
        "go.sum"
    ]
    ignore_size_threshold: int = 50000
    use_docker_isolation: bool = False

class Config(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")
    
    llm: LLMConfig = Field(default_factory=LLMConfig)
    agent: Dict[str, AgentLLMConfig] = Field(default_factory=dict)
    log: LogConfig = Field(default_factory=LogConfig)

    
    @property
    def db(self) -> DatabaseConfig:
        return DatabaseConfig(url=self.database_url)
    ui: UIConfig = Field(default_factory=UIConfig)
    fs: FileSystemConfig = Field(default_factory=FileSystemConfig)
    prompt: PromptConfig = Field(default_factory=PromptConfig)
    
    # Additional settings
    secret_key: str = Field(validation_alias="SECRET_KEY")
    app_secret_key: str = Field(validation_alias="APP_SECRET_KEY")
    redis_url: str = "redis://localhost:6379"
    vercel_token: str = ""
    database_url: str = Field(default="sqlite+aiosqlite:///data/database/samokoder.db", validation_alias="SAMOKODER_DATABASE_URL")
    environment: str = Field(default="development", validation_alias="ENVIRONMENT")
    
    # SMTP settings
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_sender_email: str = ""
    
    # GitHub OAuth settings
    github_client_id: str = ""
    github_client_secret: str = ""

    openrouter_api_key: Optional[str] = None
    openrouter_endpoint: Optional[str] = None

    def llm_for_agent(self, agent_name: str = "default") -> AgentLLMConfig:
        """Get LLM configuration for a specific agent."""
        if agent_name in self.agent:
            return self.agent[agent_name]
        
        # Return default configuration
        default_config = AgentLLMConfig()
        if "default" in self.agent:
            default_config = self.agent["default"]
        
        return default_config

class ConfigLoader:
    """Configuration loader class."""
    
    def __init__(self):
        self.config_path = None
        self.config = None
    
    def load(self, config_path: Union[str, Path]) -> Config:
        """Load configuration from a JSON file."""
        self.config_path = str(config_path)
        
        if not os.path.exists(self.config_path):
            self.config = Config()
            return self.config
        
        with open(self.config_path, 'r', encoding='utf-8') as f:
            # Handle comments in JSON
            content = f.read()
            # Remove comments (lines starting with //)
            lines = [line for line in content.split('\n') if not line.strip().startswith('//')]
            content = '\n'.join(lines)
            
            try:
                data = json.loads(content)
                self.config = Config(**data)
            except json.JSONDecodeError as e:
                raise ValueError("Unable to parse JSON") from e
        
        return self.config
    
    @classmethod
    def from_json(cls, json_str: str) -> Config:
        """Create configuration from JSON string."""
        try:
            data = json.loads(json_str)
            return Config(**data)
        except json.JSONDecodeError:
            return Config()

# Global configuration loader and getter
loader = ConfigLoader()

def get_config() -> Config:
    """Get the current configuration."""
    # Always create a new config to ensure env vars are read
    return Config()
