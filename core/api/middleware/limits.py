from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session
from samokoder.core.db.session import get_db
from samokoder.core.api.dependencies import get_current_user
from samokoder.core.db.models.user import User, Tier, Project
from datetime import datetime, timedelta
import calendar

def project_limits(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    now = datetime.utcnow()
    month_start = now.replace(day=1)
    month_end = month_start + timedelta(days=calendar.monthrange(now.year, now.month)[1])
    
    monthly_projects = db.query(Project).filter(
        Project.user_id == current_user.id,
        Project.created_at >= month_start,
        Project.created_at <= month_end
    ).count()
    
    total_projects = db.query(Project).filter(Project.user_id == current_user.id).count()
    
    limits = {
        Tier.FREE: {'monthly': 2, 'total': 2},
        Tier.STARTER: {'monthly': 10, 'total': 100},
        Tier.PRO: {'monthly': 50, 'total': float('inf')},
        Tier.TEAM: {'monthly': float('inf'), 'total': float('inf')}
    }
    limit = limits[current_user.tier]
    
    if monthly_projects >= limit['monthly'] or total_projects >= limit['total']:
        raise HTTPException(status_code=402, detail=f"Project limit exceeded for tier {current_user.tier.value}. Upgrade to continue.")
    
    current_user.projects_monthly_count = monthly_projects + 1
    if total_projects < limit['total']:
        current_user.projects_total = total_projects + 1
    db.commit()
