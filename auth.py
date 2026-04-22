from fastapi import Header, HTTPException
from database import get_db

def verify_api_key(x_api_key: str = Header(...)):
    """
    Every request to Anchor must include a valid API key.
    No key = no access. Simple as that.
    """
    db = get_db()
    result = db.table("anchor_clients")\
        .select("*")\
        .eq("api_key", x_api_key)\
        .eq("is_active", True)\
        .execute()

    if not result.data:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")

    return result.data[0]
