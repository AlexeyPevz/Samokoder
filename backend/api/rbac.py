"""
RBAC (Role-Based Access Control) endpoints
Базовая реализация системы ролей и разрешений
"""

from fastapi import APIRouter, Depends, HTTPException, status
from backend.auth.dependencies import get_current_user
from backend.models.requests import RoleCreateRequest, PermissionAssignRequest
from backend.models.responses import RoleResponse, PermissionResponse
from backend.adapters.adapter_factory import get_adapter_factory
from typing import Dict, List
import uuid

router = APIRouter()

# Получение адаптера безопасности
adapter_factory = get_adapter_factory()
security_adapter = adapter_factory.get_security_adapter()

@router.get("/roles", response_model=List[RoleResponse])
async def get_roles(current_user: dict = Depends(get_current_user)):
    """Получить список всех ролей"""
    try:
        roles = security_adapter.rbac_service.get_all_roles()
        return [RoleResponse(
            id=role.id,
            name=role.name,
            description=role.description,
            permissions=role.permissions
        ) for role in roles]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ошибка получения ролей: {str(e)}"
        )

@router.get("/permissions", response_model=List[PermissionResponse])
async def get_permissions(current_user: dict = Depends(get_current_user)):
    """Получить список всех разрешений"""
    try:
        permission_list = []
        for perm_id, perm_data in permissions.items():
            permission_list.append(PermissionResponse(
                id=perm_data["id"],
                name=perm_data["name"],
                description=perm_data["description"]
            ))
        return permission_list
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ошибка получения разрешений: {str(e)}"
        )

@router.get("/users/{user_id}/roles", response_model=List[str])
async def get_user_roles(
    user_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Получить роли пользователя"""
    try:
        # Проверяем, что пользователь запрашивает свои роли или является админом
        if current_user["id"] != user_id and "admin" not in user_roles.get(current_user["id"], []):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Недостаточно прав для просмотра ролей пользователя"
            )
        
        return user_roles.get(user_id, ["user"])  # По умолчанию роль "user"
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ошибка получения ролей пользователя: {str(e)}"
        )

@router.post("/users/{user_id}/roles")
async def assign_role(
    user_id: str,
    role_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Назначить роль пользователю"""
    try:
        # Проверяем, что текущий пользователь - админ
        if "admin" not in user_roles.get(current_user["id"], []):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Недостаточно прав для назначения ролей"
            )
        
        # Проверяем, что роль существует
        if role_id not in roles:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Роль не найдена"
            )
        
        # Назначаем роль
        if user_id not in user_roles:
            user_roles[user_id] = []
        
        if role_id not in user_roles[user_id]:
            user_roles[user_id].append(role_id)
        
        return {"message": f"Роль {role_id} назначена пользователю {user_id}"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ошибка назначения роли: {str(e)}"
        )

@router.delete("/users/{user_id}/roles/{role_id}")
async def remove_role(
    user_id: str,
    role_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Удалить роль у пользователя"""
    try:
        # Проверяем, что текущий пользователь - админ
        if "admin" not in user_roles.get(current_user["id"], []):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Недостаточно прав для удаления ролей"
            )
        
        # Удаляем роль
        if user_id in user_roles and role_id in user_roles[user_id]:
            user_roles[user_id].remove(role_id)
            return {"message": f"Роль {role_id} удалена у пользователя {user_id}"}
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Роль не найдена у пользователя"
            )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ошибка удаления роли: {str(e)}"
        )

@router.get("/check-permission")
async def check_permission(
    permission: str,
    current_user: dict = Depends(get_current_user)
):
    """Проверить разрешение у текущего пользователя"""
    try:
        user_id = current_user["id"]
        user_role_list = user_roles.get(user_id, ["user"])
        
        # Проверяем разрешения для каждой роли пользователя
        for role_id in user_role_list:
            if role_id in roles:
                role_permissions = roles[role_id]["permissions"]
                if "*" in role_permissions or permission in role_permissions:
                    return {
                        "has_permission": True,
                        "permission": permission,
                        "granted_by_role": role_id
                    }
        
        return {
            "has_permission": False,
            "permission": permission,
            "user_roles": user_role_list
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ошибка проверки разрешения: {str(e)}"
        )