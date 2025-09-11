"""
API для безопасной загрузки файлов
"""

from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Request
from fastapi.responses import JSONResponse
from typing import List, Optional
import logging

from backend.auth.dependencies import get_current_user
from backend.middleware.secure_rate_limiter import file_upload_rate_limit
from backend.security.file_upload_security import validate_file, save_file, scan_file_for_malware, get_file_info, delete_file
from backend.security.input_validator import validate_path_traversal
from backend.models.responses import FileUploadResponse, FileInfoResponse
from backend.security.secure_error_handler import create_error_context, handle_generic_error, ErrorSeverity

logger = logging.getLogger(__name__)

router = APIRouter()

@router.post("/upload", response_model=FileUploadResponse)
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    project_id: str = None,
    current_user: dict = Depends(get_current_user),
    rate_limit: dict = Depends(file_upload_rate_limit)
):
    """Безопасная загрузка файла"""
    context = create_error_context(request, ErrorSeverity.MEDIUM)
    
    try:
        # Валидируем project_id
        if not project_id or not validate_path_traversal(project_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid project ID"
            )
        
        # Читаем содержимое файла
        file_content = await file.read()
        
        # Валидируем файл
        is_valid, message, mime_type = await validate_file(file_content, file.filename)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=message
            )
        
        # Сохраняем файл
        success, save_message, file_path = await save_file(
            file_content, 
            file.filename, 
            current_user["id"], 
            project_id
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=save_message
            )
        
        # Сканируем файл на malware
        is_clean, scan_message = await scan_file_for_malware(file_path)
        if not is_clean:
            # Удаляем зараженный файл
            await delete_file(file_path)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File rejected: {scan_message}"
            )
        
        # Получаем информацию о файле
        file_info = get_file_info(file_path)
        
        logger.info(f"File uploaded successfully: {file.filename} by user {current_user['id']}")
        
        return FileUploadResponse(
            success=True,
            message="File uploaded successfully",
            file_path=file_path,
            filename=file.filename,
            mime_type=mime_type,
            size=len(file_content),
            file_info=file_info
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error uploading file: {e}")
        return handle_generic_error(e, context)

@router.post("/upload-multiple", response_model=List[FileUploadResponse])
async def upload_multiple_files(
    request: Request,
    files: List[UploadFile] = File(...),
    project_id: str = None,
    current_user: dict = Depends(get_current_user),
    rate_limit: dict = Depends(file_upload_rate_limit)
):
    """Безопасная загрузка нескольких файлов"""
    context = create_error_context(request, ErrorSeverity.MEDIUM)
    
    try:
        # Проверяем количество файлов
        if len(files) > 10:  # Максимум 10 файлов за раз
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Too many files. Maximum 10 files per upload."
            )
        
        # Валидируем project_id
        if not project_id or not validate_path_traversal(project_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid project ID"
            )
        
        results = []
        
        for file in files:
            try:
                # Читаем содержимое файла
                file_content = await file.read()
                
                # Валидируем файл
                is_valid, message, mime_type = await validate_file(file_content, file.filename)
                if not is_valid:
                    results.append(FileUploadResponse(
                        success=False,
                        message=f"Validation failed: {message}",
                        filename=file.filename
                    ))
                    continue
                
                # Сохраняем файл
                success, save_message, file_path = await save_file(
                    file_content, 
                    file.filename, 
                    current_user["id"], 
                    project_id
                )
                
                if not success:
                    results.append(FileUploadResponse(
                        success=False,
                        message=f"Save failed: {save_message}",
                        filename=file.filename
                    ))
                    continue
                
                # Сканируем файл на malware
                is_clean, scan_message = await scan_file_for_malware(file_path)
                if not is_clean:
                    # Удаляем зараженный файл
                    await delete_file(file_path)
                    results.append(FileUploadResponse(
                        success=False,
                        message=f"File rejected: {scan_message}",
                        filename=file.filename
                    ))
                    continue
                
                # Получаем информацию о файле
                file_info = get_file_info(file_path)
                
                results.append(FileUploadResponse(
                    success=True,
                    message="File uploaded successfully",
                    file_path=file_path,
                    filename=file.filename,
                    mime_type=mime_type,
                    size=len(file_content),
                    file_info=file_info
                ))
                
            except Exception as e:
                logger.error(f"Error uploading file {file.filename}: {e}")
                results.append(FileUploadResponse(
                    success=False,
                    message=f"Upload failed: {str(e)}",
                    filename=file.filename
                ))
        
        logger.info(f"Multiple files upload completed: {len(files)} files by user {current_user['id']}")
        
        return results
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error uploading multiple files: {e}")
        return handle_generic_error(e, context)

@router.get("/info/{file_path:path}", response_model=FileInfoResponse)
async def get_file_information(
    request: Request,
    file_path: str,
    current_user: dict = Depends(get_current_user)
):
    """Получает информацию о файле"""
    context = create_error_context(request, ErrorSeverity.LOW)
    
    try:
        # Валидируем путь к файлу
        if not validate_path_traversal(file_path):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid file path"
            )
        
        # Получаем информацию о файле
        file_info = get_file_info(file_path)
        if not file_info:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="File not found"
            )
        
        return FileInfoResponse(
            success=True,
            file_info=file_info
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting file info: {e}")
        return handle_generic_error(e, context)

@router.delete("/delete/{file_path:path}")
async def delete_uploaded_file(
    request: Request,
    file_path: str,
    current_user: dict = Depends(get_current_user)
):
    """Удаляет загруженный файл"""
    context = create_error_context(request, ErrorSeverity.MEDIUM)
    
    try:
        # Валидируем путь к файлу
        if not validate_path_traversal(file_path):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid file path"
            )
        
        # Удаляем файл
        success = await delete_file(file_path)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="File not found or could not be deleted"
            )
        
        logger.info(f"File deleted: {file_path} by user {current_user['id']}")
        
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "message": "File deleted successfully"
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting file: {e}")
        return handle_generic_error(e, context)