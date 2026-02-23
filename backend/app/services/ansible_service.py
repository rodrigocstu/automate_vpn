from .ansible_tasks import run_ansible_playbook
from ..core.config import settings
import yaml

class AnsibleService:
    @staticmethod
    def launch_job(config: dict, check_mode: bool = False):
        """
        Prepara los datos y lanza el trabajo a la cola de Celery.
        """
        # Generar inventario dinámico basado en la configuración (ejemplo simplificado)
        inventory = {
            "all": {
                "hosts": {
                    config.get("firewall_ip", "localhost"): {
                        "ansible_user": config.get("username"),
                        "ansible_httpapi_pass": config.get("password"),
                        "ansible_network_os": "paloaltonetworks.panos.panos",
                        "ansible_connection": "httpapi",
                        "ansible_httpapi_use_ssl": True,
                        "ansible_httpapi_validate_certs": False
                    }
                }
            }
        }
        
        inventory_yaml = yaml.dump(inventory)
        
        # Encolar el trabajo
        task = run_ansible_playbook.delay(
            playbook_data=config,
            inventory_data=inventory_yaml,
            check_mode=check_mode
        )
        
        return task.id

ansible_service = AnsibleService()
