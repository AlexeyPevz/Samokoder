"""
Setup Dependency Injection Container
"""
import logging
from backend.core.container import container
from backend.contracts.ai_service import AIServiceProtocol
from backend.contracts.database import DatabaseServiceProtocol
from backend.services.implementations.ai_service_impl import AIServiceImpl
from backend.services.implementations.database_service_impl import DatabaseServiceImpl

logger = logging.getLogger(__name__)

def setup_di_container():
    """Setup the Dependency Injection container with all services"""
    
    logger.info("Setting up Dependency Injection container...")
    
    # Register AI Service
    container.register(AIServiceProtocol, AIServiceImpl, singleton=True)
    logger.debug("Registered AIServiceProtocol -> AIServiceImpl")
    
    # Register Database Service
    container.register(DatabaseServiceProtocol, DatabaseServiceImpl, singleton=True)
    logger.debug("Registered DatabaseServiceProtocol -> DatabaseServiceImpl")
    
    # TODO: Register other services as they are implemented
    # container.register(AuthServiceProtocol, AuthServiceImpl, singleton=True)
    # container.register(FileServiceProtocol, FileServiceImpl, singleton=True)
    # container.register(NotificationServiceProtocol, NotificationServiceImpl, singleton=True)
    
    logger.info("Dependency Injection container setup complete")
    
    # Log registered services
    services = container.get_registered_services()
    logger.info(f"Registered services: {list(services.keys())}")

def get_ai_service() -> AIServiceProtocol:
    """Get AI service from container"""
    return container.get(AIServiceProtocol)

def get_database_service() -> DatabaseServiceProtocol:
    """Get database service from container"""
    return container.get(DatabaseServiceProtocol)

# Setup container on import
setup_di_container()