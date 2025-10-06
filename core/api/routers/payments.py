from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
import requests
import hmac
import hashlib
from datetime import datetime
from samokoder.core.api.dependencies import get_current_user
from samokoder.core.db.models.user import User, Tier
from samokoder.core.config import get_config
from samokoder.core.db.session import get_db
from sqlalchemy.orm import Session

router = APIRouter(prefix="/api/v1", tags=["payments"])

class SubscribeRequest(BaseModel):
    tier: str

class WebhookData(BaseModel):
    AccountId: int
    Status: str

@router.post("/subscribe")
async def subscribe(request: SubscribeRequest, current_user: User = Depends(get_current_user)):
    config = get_config()
    public_id = config.cloudpayments_public_id
    if not public_id:
        raise HTTPException(status_code=500, detail="Payments not configured")
    
    amounts = {'starter': 490, 'pro': 1490, 'team': 2490}
    if request.tier not in amounts:
        raise HTTPException(status_code=400, detail="Invalid tier")
    
    amount = amounts[request.tier]
    description = f"Upgrade to {request.tier.capitalize()}"
    
    payload = {
        'PublicId': public_id,
        'Amount': amount,
        'Currency': 'RUB',
        'InvoiceId': f"inv_{current_user.id}_{int(datetime.now().timestamp())}",
        'Description': description,
        'CustomerReceipt': {
            'Items': [{
                'Name': description,
                'Price': amount,
                'Quantity': 1,
                'TaxationSystem': 1,
                'PaymentObject': 1,
                'PaymentMethod': 1
            }],
            'TaxationSystem': 1,
            'Customer': {'Email': current_user.email}
        },
        'AccountId': current_user.id
    }
    
    response = requests.post("https://api.cloudpayments.ru/payments/cards", json=payload)
    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="Payment init failed")
    
    data = response.json()
    if data['Model']['Status'] != 'Success':
        raise HTTPException(status_code=400, detail="Payment init error")
    
    invoice_url = data['Model']['Confirmation']['ConfirmationUrl']
    return {"invoice_url": invoice_url, "tier": request.tier}

@router.post("/webhook")
async def webhook(request: Request, db: Session = Depends(get_db)):
    config = get_config()
    secret_key = config.cloudpayments_secret_key
    body = await request.body()
    signature = request.headers.get('Content-HMAC', '')
    
    expected = hmac.new(secret_key.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise HTTPException(status_code=401, detail="Invalid signature")
    
    data = WebhookData(**request.json())
    if data.Status != 'Charged':
        return {"status": "ignored"}
    
    user = db.query(User).filter(User.id == data.AccountId).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Update tier
    user.tier = Tier.STARTER  # Map from payment
    db.commit()
    
    return {"status": "updated"}
