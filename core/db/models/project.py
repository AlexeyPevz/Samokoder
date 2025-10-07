"""
Оптимизированная модель проекта с индексами и улучшенными запросами.

Исправлены проблемы:
- Добавлены индексы для производительности
- Исправлены N+1 запросы с selectinload
- Оптимизированы сложные запросы
"""

import re
from datetime import datetime
from typing import TYPE_CHECKING, Optional, Union, List
from unicodedata import normalize
from uuid import UUID, uuid4

from sqlalchemy import (
    and_, delete, select, func, ForeignKey, JSON, Index, text,
    String, DateTime
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import (
    Mapped, mapped_column, relationship, selectinload,
    DeclarativeBase, declared_attr
)

from samokoder.core.db.models.base import Base

if TYPE_CHECKING:
    from samokoder.core.db.models import Branch, ProjectState
    from samokoder.core.db.models.user import User


class Project(Base):
    __tablename__ = "projects"

    # ID and parent FKs
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)

    # Attributes
    name: Mapped[str] = mapped_column(String(100), index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, 
        server_default=func.now(), 
        index=True
    )
    folder_name: Mapped[str] = mapped_column(
        String(100),
        default=lambda context: Project.get_folder_from_project_name(
            context.get_current_parameters()["name"]
        )
    )
    samokoder_state: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Relationships с оптимизацией
    user: Mapped["User"] = relationship(back_populates="projects")
    branches: Mapped[List["Branch"]] = relationship(
        back_populates="project", 
        cascade="all, delete-orphan",
        lazy="selectin"  # Оптимизация загрузки
    )

    # Индексы для производительности
    __table_args__ = (
        Index('idx_projects_user_created', 'user_id', 'created_at'),
        Index('idx_projects_user_name', 'user_id', 'name'),
        Index('idx_projects_folder_name', 'folder_name'),
    )

    @staticmethod
    async def get_by_id(
        session: "AsyncSession", 
        project_id: Union[str, UUID]
    ) -> Optional["Project"]:
        """
        Получить проект по ID с оптимизированным запросом.
        
        Использует selectinload для предотвращения N+1 проблем.
        """
        if not isinstance(project_id, UUID):
            try:
                project_id = UUID(project_id)
            except ValueError:
                return None

        # Оптимизированный запрос с загрузкой связанных данных
        query = (
            select(Project)
            .options(
                selectinload(Project.branches).selectinload(
                    lambda branch: branch.states  # type: ignore
                )
            )
            .where(Project.id == project_id)
        )
        
        result = await session.execute(query)
        return result.scalar_one_or_none()

    async def get_branch(
        self, 
        session: "AsyncSession", 
        name: Optional[str] = None
    ) -> Optional["Branch"]:
        """
        Получить ветку проекта по имени с оптимизацией.
        """
        from samokoder.core.db.models.branch import Branch

        if name is None:
            name = Branch.DEFAULT

        # Прямой запрос без дополнительных JOIN
        query = select(Branch).where(
            Branch.project_id == self.id,
            Branch.name == name
        )
        
        result = await session.execute(query)
        return result.scalar_one_or_none()

    @staticmethod
    async def get_all_projects(
        session: "AsyncSession", 
        user_id: Optional[int] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None
    ) -> List["Project"]:
        """
        Получить все проекты с оптимизированными запросами.
        
        Поддерживает фильтрацию по пользователю и пагинацию.
        """
        from samokoder.core.db.models.branch import Branch
        from samokoder.core.db.models.project_state import ProjectState

        # CTE для получения последней версии каждого проекта
        latest_state_subq = (
            select(
                ProjectState.branch_id,
                func.max(ProjectState.step_index).label("max_index")
            )
            .group_by(ProjectState.branch_id)
            .subquery()
        )

        # Оптимизированный основной запрос
        query = (
            select(Project)
            .options(
                selectinload(Project.branches).selectinload(
                    lambda branch: branch.states  # type: ignore
                )
            )
            .join(Branch, Project.branches)
            .join(ProjectState, Branch.states)
            .join(
                latest_state_subq,
                and_(
                    ProjectState.branch_id == latest_state_subq.c.branch_id,
                    ProjectState.step_index == latest_state_subq.c.max_index,
                ),
            )
        )

        # Фильтрация по пользователю
        if user_id is not None:
            query = query.where(Project.user_id == user_id)

        # Сортировка по дате создания (новые первыми)
        query = query.order_by(Project.created_at.desc())

        # Пагинация
        if offset is not None:
            query = query.offset(offset)
        if limit is not None:
            query = query.limit(limit)

        result = await session.execute(query)
        return list(result.scalars().unique())

    @staticmethod
    async def get_projects_by_user(
        session: "AsyncSession", 
        user_id: int,
        limit: Optional[int] = None,
        offset: Optional[int] = None
    ) -> List["Project"]:
        """
        Получить проекты конкретного пользователя.
        
        Оптимизированный запрос для одного пользователя.
        """
        query = (
            select(Project)
            .options(selectinload(Project.branches))
            .where(Project.user_id == user_id)
            .order_by(Project.created_at.desc())
        )

        if offset is not None:
            query = query.offset(offset)
        if limit is not None:
            query = query.limit(limit)

        result = await session.execute(query)
        return list(result.scalars().all())

    @staticmethod
    async def search_projects(
        session: "AsyncSession", 
        search_term: str,
        user_id: Optional[int] = None,
        limit: int = 20
    ) -> List["Project"]:
        """
        Поиск проектов по названию.
        
        Использует индексы для быстрого поиска.
        """
        # Очистка поискового запроса
        search_clean = re.sub(r'[^\w\s]', ' ', search_term).strip()
        if not search_clean:
            return []

        # Поиск с использованием ILIKE для PostgreSQL
        search_filter = Project.name.ilike(f'%{search_clean}%')
        
        if user_id is not None:
            search_filter = and_(search_filter, Project.user_id == user_id)

        query = (
            select(Project)
            .options(selectinload(Project.branches))
            .where(search_filter)
            .order_by(Project.created_at.desc())
            .limit(limit)
        )

        result = await session.execute(query)
        return list(result.scalars().all())

    @staticmethod
    def get_folder_from_project_name(name: str) -> str:
        """
        Получить имя папки из названия проекта.
        
        Оптимизированная версия с лучшей обработкой Unicode.
        """
        # Нормализация Unicode (убираем акценты)
        name = normalize("NFKD", name).encode("ascii", "ignore").decode("utf-8")
        
        # Замена пробелов и пунктуации на дефисы
        name = re.sub(r'[^\w\s-]', '', name)
        name = re.sub(r'[\s_-]+', '-', name)
        
        return name.lower().strip('-')

    @staticmethod
    async def delete_by_id(
        session: "AsyncSession", 
        project_id: UUID  # FIX: Use UUID instead of undefined GUID
    ) -> bool:
        """
        Удалить проект по ID.
        
        Возвращает True если проект был удален.
        """
        result = await session.execute(
            delete(Project).where(Project.id == project_id)
        )
        return result.rowcount > 0

    @staticmethod
    async def get_project_stats(
        session: "AsyncSession", 
        user_id: Optional[int] = None
    ) -> dict:
        """
        Получить статистику по проектам.
        
        Оптимизированный запрос для дашборда.
        """
        query = select(
            func.count(Project.id).label('total_projects'),
            func.count(Project.id.filter(Project.created_at >= func.now() - text('INTERVAL 30 days'))).label('projects_last_30_days'),
            func.avg(func.length(Project.name)).label('avg_name_length')
        )
        
        if user_id is not None:
            query = query.where(Project.user_id == user_id)

        result = await session.execute(query)
        row = result.first()
        
        return {
            'total_projects': row.total_projects or 0,
            'projects_last_30_days': row.projects_last_30_days or 0,
            'avg_name_length': float(row.avg_name_length or 0)
        }
