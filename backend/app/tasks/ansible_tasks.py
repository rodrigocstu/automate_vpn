import os
import shutil
import ansible_runner
from celery import Celery
from ..core.config import settings
from ..db.session import SessionLocal
from ..models.ansible import AnsibleJob
import json

celery_app = Celery("tasks", broker=settings.REDIS_URL, backend=settings.REDIS_URL)

@celery_app.task(bind=True)
def run_ansible_playbook(self, playbook_data: dict, inventory_data: str, env_vars: dict = None, check_mode: bool = False):
    """
    Ejecuta un playbook de Ansible de forma asíncrona y persiste el resultado.
    """
    db = SessionLocal()
    job = db.query(AnsibleJob).filter(AnsibleJob.task_id == self.request.id).first()
    if not job:
        job = AnsibleJob(task_id=self.request.id, module_type=playbook_data.get("module_type"), status="running", is_check_mode=check_mode)
        db.add(job)
        db.commit()

    project_dir = os.path.join(settings.ANSIBLE_DATA_DIR, "projects", str(self.request.id))
    os.makedirs(project_dir, exist_ok=True)
    
    # Escribir inventario
    inventory_path = os.path.join(project_dir, "hosts")
    with open(inventory_path, "w") as f:
        f.write(inventory_data)
        
    # Escribir playbook (En una fase posterior esto será dinámico)
    playbook_file = "site.yml"
    playbook_path = os.path.join(project_dir, playbook_file)
    with open(playbook_path, "w") as f:
        # Aquí se escribiría el Playbook generado por el modulo vpn_globalprotect
        f.write(playbook_data.get("yaml_content", "---\n- hosts: all\n  gather_facts: no\n  tasks:\n    - debug: msg='Placeholder'"))
    
    # Configuración de ejecución
    runner_args = {
        "private_data_dir": project_dir,
        "playbook": playbook_path,
        "inventory": inventory_path,
        "extravars": playbook_data.get("params", {}),
        "envvars": env_vars or {},
    }
    
    if check_mode:
        runner_args["cmdline"] = "--check"

    try:
        r = ansible_runner.run(**runner_args)
        
        job.status = r.status
        job.result_stats = r.stats
        job.full_output = r.stdout.read() if hasattr(r.stdout, 'read') else str(r.stdout)
        db.commit()

        return {
            "status": r.status,
            "rc": r.rc,
            "stats": r.stats,
            "job_id": job.id
        }
    except Exception as e:
        job.status = "failed"
        job.full_output = str(e)
        db.commit()
        return {"status": "failed", "error": str(e)}
    finally:
        db.close()
