from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from ..services.ansible_service import ansible_service
from ..services.access_service import AccessService
from ..services.portal_gateway_service import PortalGatewayService
from ..services.entity_service import EntityService
from ..services.policy_service import PolicyService
from ..services.system_service import SystemService
from ..services.networking_service import NetworkingService
from ..services.nat_service import NatService
from celery.result import AsyncResult

router = APIRouter()

# --- SCHEMAS ---

class AccessLaunchSchema(BaseModel):
    firewall_ip: str
    username: str
    password: str
    ritm: str
    user_vpn: str
    tipo: str # INT / EXT
    ips: list = []
    puertos: list = []
    check_mode: bool = False

class PortalLaunchSchema(BaseModel):
    firewall_ip: str
    username: str
    password: str
    name: str
    interface: str = "ethernet1/1"
    auth_profile: str = "None"
    check_mode: bool = False

class GatewayLaunchSchema(BaseModel):
    firewall_ip: str
    username: str
    password: str
    name: str
    interface: str = "ethernet1/1"
    auth_profile: str = "None"
    check_mode: bool = False

class AuthProfileLaunchSchema(BaseModel):
    firewall_ip: str
    username: str
    password: str
    name: str
    type: str = "ldap"
    server_profile: str = "None"
    check_mode: bool = False

class EntityLaunchSchema(BaseModel):
    firewall_ip: str
    username: str
    password: str
    addresses: list = [] # list of {name, value}
    services: list = [] # list of {name, protocol, port}
    address_groups: list = [] # list of {name, static_value}
    check_mode: bool = False

class PolicyLaunchSchema(BaseModel):
    firewall_ip: str
    username: str
    password: str
    tags: list = [] # list of {name, color}
    rules: list = [] # list of {name, source_zone, ..., location}
    check_mode: bool = False

class SystemLaunchSchema(BaseModel):
    firewall_ip: str
    username: str
    password: str
    checkpoint_name: str = None
    create_checkpoint: bool = False
    commit: bool = False
    type_cmd: dict = None # {name, xpath, element}
    check_mode: bool = False

class NetworkingLaunchSchema(BaseModel):
    firewall_ip: str
    username: str
    password: str
    interface_name: str = "ethernet1/1"
    zone_name: str = "untrusted"
    mode: str = "layer3"
    destination: str = None # For static route
    next_hop: str = None
    vr_name: str = "default"
    check_mode: bool = False

class NatLaunchSchema(BaseModel):
    firewall_ip: str
    username: str
    password: str
    name: str
    source_zone: str = "untrusted"
    destination_zone: str = "untrusted"
    source_address: list = ["any"]
    destination_address: list = ["any"]
    nat_type: str = "source"
    translated_address: str = None
    check_mode: bool = False

# --- ENDPOINTS ---

@router.post("/launch/access")
async def launch_access_job(payload: AccessLaunchSchema):
    yaml_content = AccessService.generate_playbook({
        "ritm": payload.ritm,
        "username": payload.user_vpn,
        "tipo": payload.tipo,
        "ips": payload.ips,
        "puertos": payload.puertos
    })
    return _enqueue(payload, yaml_content, "access")

@router.post("/launch/portal")
async def launch_portal_job(payload: PortalLaunchSchema):
    yaml_content = PortalGatewayService.generate_portal_playbook(payload.dict())
    return _enqueue(payload, yaml_content, "portal")

@router.post("/launch/gateway")
async def launch_gateway_job(payload: GatewayLaunchSchema):
    yaml_content = PortalGatewayService.generate_gateway_playbook(payload.dict())
    return _enqueue(payload, yaml_content, "gateway")

@router.post("/launch/auth-profile")
async def launch_auth_profile_job(payload: AuthProfileLaunchSchema):
    yaml_content = PortalGatewayService.generate_auth_profile_playbook(payload.dict())
    return _enqueue(payload, yaml_content, "auth-profile")

@router.post("/launch/entities")
async def launch_entity_job(payload: EntityLaunchSchema):
    yaml_content = EntityService.generate_entity_playbook(payload.dict())
    return _enqueue(payload, yaml_content, "entity")

@router.post("/launch/policies")
async def launch_policy_job(payload: PolicyLaunchSchema):
    yaml_content = PolicyService.generate_policy_playbook(payload.dict())
    return _enqueue(payload, yaml_content, "policy")

@router.post("/launch/system")
async def launch_system_job(payload: SystemLaunchSchema):
    yaml_content = SystemService.generate_system_playbook(payload.dict())
    return _enqueue(payload, yaml_content, "system")

@router.post("/launch/networking")
async def launch_networking_job(payload: NetworkingLaunchSchema):
    if payload.destination: # If it has destination, it's a static route
        yaml_content = NetworkingService.generate_static_route_playbook(payload.dict())
    else:
        yaml_content = NetworkingService.generate_interface_playbook(payload.dict())
    return _enqueue(payload, yaml_content, "networking")

@router.post("/launch/nat")
async def launch_nat_job(payload: NatLaunchSchema):
    yaml_content = NatService.generate_nat_playbook(payload.dict())
    return _enqueue(payload, yaml_content, "nat")

def _enqueue(payload, yaml_content, module_type):
    try:
        job_config = payload.dict()
        job_config["yaml_content"] = yaml_content
        job_config["module_type"] = module_type
        job_id = ansible_service.launch_job(job_config, check_mode=payload.check_mode)
        return {"job_id": job_id, "status": "queued", "playbook_preview": yaml_content}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/status/{job_id}")
async def get_job_status(job_id: str):
    res = AsyncResult(job_id)
    output = {"job_id": job_id, "status": res.status}
    if res.ready():
        output["result"] = res.result
        if isinstance(res.result, dict) and "stats" in res.result:
            output["summary"] = res.result["stats"]
    return output
