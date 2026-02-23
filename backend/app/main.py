from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

app = FastAPI(
    title="Ansible PAN-OS Automation API",
    description="Backend para la automatización de firewalls Palo Alto Networks bajo el framework ITIL 4 (Change Enablement).",
    version="1.0.0"
)

from .api import ansible_api

# ... (CORS middleware) ...

app.include_router(ansible_api.router, prefix="/api/v1/ansible", tags=["Ansible"])

@app.get("/")
async def root():
    return {"message": "Ansible PAN-OS API is running", "status": "online"}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
