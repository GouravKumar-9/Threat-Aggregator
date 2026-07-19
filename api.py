import os
import threading
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, BackgroundTasks, Query, Depends, Response, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

from core.database import (
    init_db,
    insert_iocs,
    search_ioc,
    get_all_iocs,
    get_total_count,
    get_recent_iocs,
    get_stats,
    get_user_by_username,
    set_user_mfa_secret
)
from core.feeds import fetch_feodo_tracker, fetch_urlhaus, fetch_alienvault_otx
from core.virustotal import lookup as vt_lookup
from core.abuseipdb import lookup as abuseipdb_lookup
from core.auth import (
    verify_password,
    create_access_token,
    get_current_user,
    generate_mfa_secret,
    get_mfa_uri,
    verify_mfa_code,
    decode_access_token
)

from apscheduler.schedulers.background import BackgroundScheduler
from core.database import age_out_iocs

# Load environment variables from .env if present
load_dotenv()

# ---------------------------------------------------------------------------
# Background Scheduler
# ---------------------------------------------------------------------------
scheduler = BackgroundScheduler()

# ---------------------------------------------------------------------------
# Application lifecycle
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize the database on startup."""
    init_db()
    
    # Auto-provision admin user from environment variables
    admin_user = os.getenv("ADMIN_USERNAME")
    admin_pass = os.getenv("ADMIN_PASSWORD")
    if admin_user and admin_pass:
        from core.auth import get_password_hash
        if not get_user_by_username(admin_user):
            create_user(admin_user, get_password_hash(admin_pass))
            print(f"[*] Auto-provisioned admin user: {admin_user}")

    # Schedule automated background tasks
    scheduler.add_job(_run_feed_update, 'interval', minutes=60, id='feed_update')
    scheduler.add_job(age_out_iocs, 'interval', days=1, id='age_out_iocs')
    scheduler.start()
    
    yield
    
    scheduler.shutdown()

app = FastAPI(
    title="Threat Aggregator",
    description="REST API for querying and managing threat IoC feeds.",
    version="2.0.0",
    lifespan=lifespan,
)

app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")), name="static")

# Templates directory (relative to this file)
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(_BASE_DIR, "templates"))

# ---------------------------------------------------------------------------
# Background update lock — prevents concurrent feed updates
# ---------------------------------------------------------------------------
_update_lock = threading.Lock()
_update_status = {"running": False, "last_result": None}


def _run_feed_update():
    """Synchronous feed update — runs in a background thread."""
    global _update_status
    _update_status["running"] = True
    try:
        feodo = fetch_feodo_tracker()
        urlhaus = fetch_urlhaus()
        otx = fetch_alienvault_otx()
        all_iocs = feodo + urlhaus + otx
        new_count = insert_iocs(all_iocs)
        _update_status["last_result"] = {
            "status": "success",
            "new_iocs": new_count,
            "total_fetched": len(all_iocs),
        }
    except Exception as exc:
        _update_status["last_result"] = {"status": "error", "detail": str(exc)}
    finally:
        _update_status["running"] = False

# ---------------------------------------------------------------------------
# Auth Routes & Pages
# ---------------------------------------------------------------------------

@app.get("/login", response_class=HTMLResponse, include_in_schema=False)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
async def dashboard_page(request: Request):
    try:
        user = await get_current_user(request)
        return templates.TemplateResponse("dashboard.html", {"request": request, "user": user})
    except HTTPException:
        return RedirectResponse(url="/login", status_code=303)

@app.get("/threats", response_class=HTMLResponse, include_in_schema=False)
async def threats_page(request: Request):
    try:
        user = await get_current_user(request)
        return templates.TemplateResponse("threats.html", {"request": request, "user": user})
    except HTTPException:
        return RedirectResponse(url="/login", status_code=303)

@app.get("/settings", response_class=HTMLResponse, include_in_schema=False)
async def settings_page(request: Request):
    try:
        user = await get_current_user(request)
        return templates.TemplateResponse("settings.html", {"request": request, "user": user})
    except HTTPException:
        return RedirectResponse(url="/login", status_code=303)

@app.post("/api/auth/login", summary="Login to the dashboard")
async def api_login(
    response: Response,
    username: str = Form(...),
    password: str = Form(...)
):
    user = get_user_by_username(username)
    if not user or not verify_password(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = create_access_token(data={"sub": username, "mfa_pending": False})
    response.set_cookie(key="session_token", value=token, httponly=True, max_age=86400)
    return {"status": "success", "redirect": "/dashboard"}

@app.post("/api/auth/logout", summary="Logout")
async def api_logout(response: Response):
    response.delete_cookie("session_token")
    return {"status": "success"}

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", include_in_schema=False)
async def root():
    """Redirect root to the dashboard."""
    return RedirectResponse(url="/dashboard")


@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
async def dashboard(request: Request):
    """Serves the interactive threat intelligence dashboard."""
    try:
        user = await get_current_user(request)
    except HTTPException:
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": user})


@app.get("/api/stats", summary="Aggregated statistics for the dashboard")
async def api_stats(user: dict = Depends(get_current_user)):
    return get_stats()


@app.get("/api/iocs", summary="Paginated list of all IoCs")
async def api_iocs(
    limit: int = Query(50, ge=1, le=500, description="Results per page"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    user: dict = Depends(get_current_user)
):
    total = get_total_count()
    iocs = get_all_iocs(limit=limit, offset=offset)
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "results": iocs,
    }


@app.get("/api/search", summary="Search for a specific IoC")
async def api_search(
    q: str = Query(..., min_length=1, description="IP, URL, or domain to search"),
    user: dict = Depends(get_current_user)
):
    result = search_ioc(q.strip())
    if result is None:
        raise HTTPException(status_code=404, detail=f"'{q}' not found in any threat feed. (Clean)")
    return {
        "found": True,
        "ioc_value": result[0],
        "ioc_type": result[1],
        "source": result[2],
        "timestamp": result[3],
    }


@app.get("/api/recent", summary="Recently added IoCs")
async def api_recent(
    n: int = Query(20, ge=1, le=100, description="Number of recent IoCs to return"),
    user: dict = Depends(get_current_user)
):
    return {"results": get_recent_iocs(n)}


@app.get("/api/globe_data", summary="Get IPs with coordinates for 3D Globe")
async def api_globe_data(user: dict = Depends(get_current_user)):
    # Fetch high confidence IPs with lat and lon
    iocs = get_all_iocs(limit=5000)
    globe_ips = []
    for ioc in iocs:
        if ioc["ioc_type"] == "IP" and ioc.get("lat") and ioc.get("lon"):
            globe_ips.append({
                "lat": ioc["lat"],
                "lng": ioc["lon"],
                "size": min(ioc.get("confidence_score", 50) / 100, 1.0),
                "color": "red" if ioc.get("confidence_score", 50) > 80 else "orange"
            })
    return {"points": globe_ips}


@app.post("/api/update", summary="Trigger a threat feed update")
async def api_update(
    background_tasks: BackgroundTasks,
    user: dict = Depends(get_current_user)
):
    if _update_status["running"]:
        return {"status": "already_running", "message": "A feed update is already in progress."}
    
    background_tasks.add_task(_run_feed_update)
    return {"status": "started", "message": "Feed update started in the background."}


@app.get("/api/update/status", summary="Check feed update status")
async def api_update_status(user: dict = Depends(get_current_user)):
    return {
        "running": _update_status["running"],
        "last_result": _update_status["last_result"],
    }


# ---------------------------------------------------------------------------
# SSE Live Notifications
# ---------------------------------------------------------------------------
from fastapi.responses import StreamingResponse
import asyncio

_sse_events = []

async def sse_generator(request: Request):
    last_idx = len(_sse_events)
    while True:
        if await request.is_disconnected():
            break
        if len(_sse_events) > last_idx:
            for ev in _sse_events[last_idx:]:
                yield f"data: {json.dumps(ev)}\n\n"
            last_idx = len(_sse_events)
        await asyncio.sleep(0.5)

@app.get("/api/stream", summary="SSE endpoint for real-time notifications", include_in_schema=False)
async def api_stream(request: Request):
    return StreamingResponse(sse_generator(request), media_type="text/event-stream")

from pydantic import BaseModel
class NotifyPayload(BaseModel):
    message: str
    ioc: str = ""
    source: str = ""
    type: str = "info" # info, warning, danger

@app.post("/api/internal/notify", summary="Internal endpoint to trigger UI toast notifications", include_in_schema=False)
async def api_internal_notify(payload: NotifyPayload):
    _sse_events.append(payload.dict())
    return {"status": "broadcasted"}


# ---------------------------------------------------------------------------
# Exports (SIEM & Firewall)
# ---------------------------------------------------------------------------

import csv
import io
from fastapi.responses import PlainTextResponse

@app.get("/api/export/csv", summary="Export IoCs as CSV for SIEM")
async def export_csv(user: dict = Depends(get_current_user)):
    iocs = get_all_iocs(limit=100000)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "ioc_value", "ioc_type", "source", "timestamp", "confidence_score", "last_seen", "stix_data"])
    for row in iocs:
        writer.writerow([
            row["id"], row["ioc_value"], row["ioc_type"], row["source"],
            row.get("timestamp", ""), row.get("confidence_score", ""),
            row.get("last_seen", ""), row.get("stix_data", "")
        ])
    return Response(content=output.getvalue(), media_type="text/csv")

@app.get("/api/export/json", summary="Export IoCs as JSON for SIEM")
async def export_json(user: dict = Depends(get_current_user)):
    iocs = get_all_iocs(limit=100000)
    return iocs

@app.get("/api/blocklist.txt", summary="Export high-confidence IPs for Firewalls")
async def export_blocklist(user: dict = Depends(get_current_user)):
    """Returns a clean, newline-separated list of malicious IPs with confidence > 70."""
    iocs = get_all_iocs(limit=100000)
    blocked_ips = [
        row["ioc_value"] for row in iocs 
        if row["ioc_type"] == "IP" and row.get("confidence_score", 50) > 70
    ]
    return PlainTextResponse("\n".join(blocked_ips))


# ---------------------------------------------------------------------------
# VirusTotal enrichment
# ---------------------------------------------------------------------------

@app.get("/api/vt/lookup", summary="VirusTotal enrichment lookup")
async def api_vt_lookup(
    q: str = Query(..., min_length=1, description="IP address, domain, or URL to look up on VirusTotal"),
    user: dict = Depends(get_current_user)
):
    try:
        result = vt_lookup(q.strip())
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        status_code = 500
        detail = str(exc)
        if hasattr(exc, "response") and exc.response is not None:
            status_code = exc.response.status_code
            try:
                vt_error = exc.response.json().get("error", {})
                detail = vt_error.get("message", detail)
            except Exception:
                pass
        raise HTTPException(status_code=status_code, detail=detail)


# ---------------------------------------------------------------------------
# AbuseIPDB enrichment
# ---------------------------------------------------------------------------

@app.get("/api/abuseipdb/lookup", summary="AbuseIPDB enrichment lookup")
async def api_abuseipdb_lookup(
    q: str = Query(..., min_length=1, description="IP address to look up on AbuseIPDB"),
    user: dict = Depends(get_current_user)
):
    try:
        result = abuseipdb_lookup(q.strip())
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        status_code = 500
        detail = str(exc)
        if hasattr(exc, "response") and exc.response is not None:
            status_code = exc.response.status_code
            try:
                errors = exc.response.json().get("errors", [])
                if errors:
                    detail = errors[0].get("detail", detail)
            except Exception:
                pass
        raise HTTPException(status_code=status_code, detail=detail)
