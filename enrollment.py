from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timezone
import hashlib
from database import get_db

router = APIRouter(prefix="/enroll", tags=["Device Enrollment"])


class DeviceEnrollRequest(BaseModel):
    employee_id: str
    device_fingerprint: str
    device_label: Optional[str] = None
    tpm_public_key: Optional[str] = None
    device_cert: Optional[str] = None


class DeviceRevokeRequest(BaseModel):
    device_fingerprint: str


def get_tenant_id(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()[:16]


def is_device_enrolled(tenant_id: str, device_fingerprint: str) -> bool:
    """Called during session validation — is this an institutional device?"""
    db = get_db()
    result = db.table("enrolled_devices").select("id").eq(
        "tenant_id", tenant_id
    ).eq(
        "device_fingerprint", device_fingerprint
    ).eq(
        "is_active", True
    ).execute()
    return bool(result.data)


@router.post("/device")
async def enroll_device(
    request: DeviceEnrollRequest,
    x_api_key: str = Header(..., alias="X-API-Key"),
    enrolled_by: str = Header(..., alias="X-Admin-ID")
):
    db = get_db()
    tenant_id = get_tenant_id(x_api_key)

    existing = db.table("enrolled_devices").select("id, is_active").eq(
        "tenant_id", tenant_id
    ).eq(
        "device_fingerprint", request.device_fingerprint
    ).execute()

    if existing.data:
        if existing.data[0]["is_active"]:
            raise HTTPException(
                status_code=409,
                detail="Device already enrolled and active for this tenant"
            )
        # Reactivate revoked device
        db.table("enrolled_devices").update({
            "is_active": True,
            "enrolled_by": enrolled_by,
            "enrolled_at": datetime.now(timezone.utc).isoformat(),
            "tpm_public_key": request.tpm_public_key,
            "device_cert": request.device_cert,
            "device_label": request.device_label
        }).eq("tenant_id", tenant_id).eq(
            "device_fingerprint", request.device_fingerprint
        ).execute()

        return {
            "status": "reactivated",
            "tenant_id": tenant_id,
            "employee_id": request.employee_id,
            "message": "Previously revoked device reactivated"
        }

    result = db.table("enrolled_devices").insert({
        "tenant_id": tenant_id,
        "employee_id": request.employee_id,
        "device_fingerprint": request.device_fingerprint,
        "device_label": request.device_label or f"{request.employee_id}'s device",
        "tpm_public_key": request.tpm_public_key,
        "device_cert": request.device_cert,
        "enrolled_by": enrolled_by,
        "is_active": True,
        "enrolled_at": datetime.now(timezone.utc).isoformat()
    }).execute()

    if not result.data:
        raise HTTPException(status_code=500, detail="Enrollment failed")

    return {
        "status": "enrolled",
        "tenant_id": tenant_id,
        "employee_id": request.employee_id,
        "device_fingerprint": request.device_fingerprint,
        "message": "Device enrolled. It will now pass hardware verification."
    }


@router.get("/devices")
async def list_enrolled_devices(
    x_api_key: str = Header(..., alias="X-API-Key")
):
    db = get_db()
    tenant_id = get_tenant_id(x_api_key)
    result = db.table("enrolled_devices").select(
        "employee_id, device_fingerprint, device_label, enrolled_by, enrolled_at, is_active"
    ).eq("tenant_id", tenant_id).execute()

    devices = result.data or []
    return {
        "tenant_id": tenant_id,
        "total": len(devices),
        "active": sum(1 for d in devices if d["is_active"]),
        "devices": devices
    }


@router.post("/device/revoke")
async def revoke_device(
    request: DeviceRevokeRequest,
    x_api_key: str = Header(..., alias="X-API-Key"),
    revoked_by: str = Header(..., alias="X-Admin-ID")
):
    db = get_db()
    tenant_id = get_tenant_id(x_api_key)

    result = db.table("enrolled_devices").update({
        "is_active": False
    }).eq("tenant_id", tenant_id).eq(
        "device_fingerprint", request.device_fingerprint
    ).execute()

    if not result.data:
        raise HTTPException(status_code=404, detail="Device not found for this tenant")

    # Log the revocation
    from watcher import log_threat
    db.table("anchor_threats").insert({
        "event_type": "device_revoked",
        "severity": "medium",
        "details": f"Device {request.device_fingerprint[:12]}... revoked by {revoked_by}",
        "detected_at": datetime.now(timezone.utc).isoformat()
    }).execute()

    return {
        "status": "revoked",
        "device_fingerprint": request.device_fingerprint,
        "message": "Device revoked. Sessions from this device will now be blocked."
    }