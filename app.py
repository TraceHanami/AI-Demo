"""
Customer Support RAG Security Demonstration Environment.
Academic testbed demonstrating Excessive Agency (OWASP LLM06) and
Unbounded Consumption (OWASP LLM04) risks and defensive mitigations.
"""

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from backend.database import init_database
from backend.routers.chat import router as chat_router
from backend.routers.security_api import router as security_router
from backend.routers.scenarios import router as scenarios_router


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "frontend", "static")
TEMPLATES_DIR = os.path.join(BASE_DIR, "frontend", "templates")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_database(reset=False)
    yield


app = FastAPI(
    title="Customer Support RAG Security Demonstration Environment",
    description="Academic research & educational platform for AI Security (OWASP LLM06 & LLM04)",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files & Jinja templates
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# Register API Routers
app.include_router(chat_router)
app.include_router(security_router)
app.include_router(scenarios_router)


@app.get("/", response_class=HTMLResponse)
def serve_index(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "Customer Support RAG Security Demonstration Environment",
        "version": "1.0.0"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
