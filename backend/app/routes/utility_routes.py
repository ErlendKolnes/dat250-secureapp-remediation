import traceback
import logging
import requests
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from app.auth import get_user_from_session
from app.config import APP_ENV

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/health")
def health():
    return {"status": "ok"}


@router.get("/status", response_class=HTMLResponse)
def status(request: Request):
    user = get_user_from_session(request)
    # Information disclosure fix (Funn 3): environment/runtime details are only
    # shown to administrators, not to anonymous visitors.
    if not user or user["role"] != "admin":
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "details": "Du har ikke tilgang til denne siden."},
            status_code=403,
        )
    return templates.TemplateResponse(
        "status.html",
        {"request": request, "user": user, "env": APP_ENV, "python": "3.11", "service": "backend"},
    )


@router.get("/resources/import", response_class=HTMLResponse)
def import_resource_get(request: Request, url: str = ""):
    user = get_user_from_session(request)
    body = ""
    error = ""
    if url:
        try:
            r = requests.get(url, timeout=5)
            body = r.text[:2000]
        except Exception as exc:
            error = str(exc)
    return templates.TemplateResponse(
        "resource_import.html",
        {"request": request, "user": user, "body": body, "url": url, "error": error},
    )


@router.post("/resources/import", response_class=HTMLResponse)
def import_resource_post(request: Request, url: str = Form(...)):
    return import_resource_get(request, url)


@router.get("/error", response_class=HTMLResponse)
def trigger_error(request: Request):
    try:
        x = 1 / 0
        return {"x": x}
    except Exception:
        # Data exposure fix (Funn 3): never send the raw traceback to the client.
        # Log it server-side and show a generic error page instead.
        logging.exception("Unhandled error in /error")
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "details": "En uventet feil oppstod. Kontakt administrator."},
            status_code=500,
        )
