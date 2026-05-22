from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timezone
import hashlib
from database import get_db

router = APIRouter(prefix="/enroll", tags=["Device Enrollment"])


# ─────────────────────────────────────────
# MODELS
# ─────────────────────────────────────────

class DeviceEnrollRequest(BaseModel):
    employee_id: str
    device_fingerprint: str
    device_label: Optional[str] = None
    tpm_public_key: Optional[str] = None
    device_cert: Optional[str] = None


class DeviceSelfEnrollRequest(BaseModel):
    employee_id: str
    ip_address: str
    user_agent: str


class DeviceRevokeRequest(BaseModel):
    device_fingerprint: str


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def get_tenant_id(api_key: str) -> str:
    """Derive tenant ID from API key — consistent across all of Anchor."""
    return hashlib.sha256(api_key.encode()).hexdigest()[:16]


def is_device_enrolled(tenant_id: str, device_fingerprint: str) -> bool:
    """
    Called during session validation.
    Returns True only if device is enrolled AND active for this tenant.
    """
    db = get_db()
    result = db.table("enrolled_devices").select("id").eq(
        "tenant_id", tenant_id
    ).eq(
        "device_fingerprint", device_fingerprint
    ).eq(
        "is_active", True
    ).execute()
    return bool(result.data)


# ─────────────────────────────────────────
# ENDPOINTS
# ─────────────────────────────────────────

@router.post("/device")
async def enroll_device(
    request: DeviceEnrollRequest,
    x_api_key: str = Header(..., alias="X-API-Key"),
    enrolled_by: str = Header(..., alias="X-Admin-ID")
):
    """
    Enroll a trusted device manually.
    IT admin provides the device fingerprint directly.
    Use /device/self-enroll for automatic agent-based enrollment.
    """
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
        # Reactivate previously revoked device
        db.table("enrolled_devices").update({
            "is_active":      True,
            "enrolled_by":    enrolled_by,
            "enrolled_at":    datetime.now(timezone.utc).isoformat(),
            "tpm_public_key": request.tpm_public_key,
            "device_cert":    request.device_cert,
            "device_label":   request.device_label
        }).eq("tenant_id", tenant_id).eq(
            "device_fingerprint", request.device_fingerprint
        ).execute()

        return {
            "status":             "reactivated",
            "tenant_id":          tenant_id,
            "employee_id":        request.employee_id,
            "device_fingerprint": request.device_fingerprint,
            "message":            "Previously revoked device reactivated."
        }

    result = db.table("enrolled_devices").insert({
        "tenant_id":          tenant_id,
        "employee_id":        request.employee_id,
        "device_fingerprint": request.device_fingerprint,
        "device_label":       request.device_label or f"{request.employee_id}'s device",
        "tpm_public_key":     request.tpm_public_key,
        "device_cert":        request.device_cert,
        "enrolled_by":        enrolled_by,
        "is_active":          True,
        "enrolled_at":        datetime.now(timezone.utc).isoformat()
    }).execute()

    if not result.data:
        raise HTTPException(status_code=500, detail="Enrollment failed")

    return {
        "status":             "enrolled",
        "tenant_id":          tenant_id,
        "employee_id":        request.employee_id,
        "device_fingerprint": request.device_fingerprint,
        "device_label":       request.device_label or f"{request.employee_id}'s device",
        "message":            "Device enrolled. It will now pass hardware verification."
    }


@router.post("/device/self-enroll")
async def self_enroll_device(
    request: DeviceSelfEnrollRequest,
    x_api_key: str = Header(..., alias="X-API-Key"),
    enrolled_by: str = Header(..., alias="X-Admin-ID")
):
    """
    Called by the enrollment agent running on the device itself.
    The device computes its own fingerprint from IP and user agent
    and self-registers — IT admin never manually types a fingerprint.

    In production: a lightweight agent installed on each institutional
    device calls this endpoint automatically on first boot.
    The IT admin simply approves from the dashboard.
    """
    from fingerprint import build_fingerprint
    db = get_db()
    tenant_id          = get_tenant_id(x_api_key)
    device_fingerprint = build_fingerprint(request.ip_address, request.user_agent)

    existing = db.table("enrolled_devices").select("id, is_active").eq(
        "tenant_id", tenant_id
    ).eq(
        "device_fingerprint", device_fingerprint
    ).execute()

    if existing.data and existing.data[0]["is_active"]:
        return {
            "status":             "already_enrolled",
            "tenant_id":          tenant_id,
            "employee_id":        request.employee_id,
            "device_fingerprint": device_fingerprint,
            "message":            "Device already enrolled and active."
        }

    db.table("enrolled_devices").insert({
        "tenant_id":          tenant_id,
        "employee_id":        request.employee_id,
        "device_fingerprint": device_fingerprint,
        "device_label":       f"{request.employee_id}'s device (auto-enrolled)",
        "enrolled_by":        enrolled_by,
        "is_active":          True,
        "enrolled_at":        datetime.now(timezone.utc).isoformat()
    }).execute()

    return {
        "status":             "enrolled",
        "tenant_id":          tenant_id,
        "employee_id":        request.employee_id,
        "device_fingerprint": device_fingerprint,
        "message":            "Device self-enrolled successfully. Hardware verification active."
    }


@router.get("/devices")
async def list_enrolled_devices(
    x_api_key: str = Header(..., alias="X-API-Key")
):
    """
    List all enrolled devices for this tenant.
    IT admin view — shows active and revoked devices.
    """
    db = get_db()
    tenant_id = get_tenant_id(x_api_key)

    result = db.table("enrolled_devices").select(
        "employee_id, device_fingerprint, device_label, enrolled_by, enrolled_at, is_active"
    ).eq("tenant_id", tenant_id).execute()

    devices = result.data or []

    return {
        "tenant_id": tenant_id,
        "total":     len(devices),
        "active":    sum(1 for d in devices if d["is_active"]),
        "revoked":   sum(1 for d in devices if not d["is_active"]),
        "devices":   devices
    }


@router.post("/device/revoke")
async def revoke_device(
    request: DeviceRevokeRequest,
    x_api_key: str = Header(..., alias="X-API-Key"),
    revoked_by: str = Header(..., alias="X-Admin-ID")
):
    """
    Revoke a device immediately.
    Use when: employee leaves, device lost/stolen, suspected compromise.
    Session from this device will fail CHECK 4 instantly.
    """
    db = get_db()
    tenant_id = get_tenant_id(x_api_key)

    result = db.table("enrolled_devices").update({
        "is_active": False
    }).eq("tenant_id", tenant_id).eq(
        "device_fingerprint", request.device_fingerprint
    ).execute()

    if not result.data:
        raise HTTPException(
            status_code=404,
            detail="Device not found for this tenant"
        )

    # Log the revocation as a security event
    db.table("anchor_threats").insert({
        "event_type":  "device_revoked",
        "severity":    "medium",
        "details":     f"Device {request.device_fingerprint[:12]}... revoked by {revoked_by}",
        "detected_at": datetime.now(timezone.utc).isoformat()
    }).execute()

    return {
        "status":             "revoked",
        "device_fingerprint": request.device_fingerprint,
        "message":            "Device revoked. Any sessions from this device are now blocked."
    }