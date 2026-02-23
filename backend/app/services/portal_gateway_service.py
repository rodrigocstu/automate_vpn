from ..core.panos_utils import PanosUtils

class PortalGatewayService:
    @staticmethod
    def generate_portal_playbook(params: dict) -> str:
        """
        Genera playbook para panos_global_protect_portal.
        """
        name = params.get("name", "GP-Portal")
        vsys = params.get("vsys", "vsys1")
        
        lines = [
            "---",
            f"- name: Configurar Portal GlobalProtect - {name}",
            "  hosts: all",
            "  connection: local",
            "  gather_facts: false",
            "  vars:",
            "    provider:",
            "      ip_address: \"{{ device_ip }}\"",
            "      username: \"{{ device_user }}\"",
            "      password: \"{{ device_pass }}\"",
            "  tasks:",
            "    - name: Asegurar Portal",
            "      paloaltonetworks.panos.panos_global_protect_portal:",
            "        provider: \"{{ provider }}\"",
            f"        name: \"{name}\"",
            f"        interface: \"{params.get('interface', 'ethernet1/1')}\"",
            f"        auth_profile: \"{params.get('auth_profile', 'None')}\"",
            f"        vsys: \"{vsys}\""
        ]
        return "\n".join(lines)

    @staticmethod
    def generate_gateway_playbook(params: dict) -> str:
        """
        Genera playbook para panos_global_protect_gateway.
        """
        name = params.get("name", "GP-Gateway")
        vsys = params.get("vsys", "vsys1")
        
        lines = [
            "---",
            f"- name: Configurar Gateway GlobalProtect - {name}",
            "  hosts: all",
            "  connection: local",
            "  gather_facts: false",
            "  vars:",
            "    provider:",
            "      ip_address: \"{{ device_ip }}\"",
            "      username: \"{{ device_user }}\"",
            "      password: \"{{ device_pass }}\"",
            "  tasks:",
            "    - name: Asegurar Gateway",
            "      paloaltonetworks.panos.panos_global_protect_gateway:",
            "        provider: \"{{ provider }}\"",
            f"        name: \"{name}\"",
            f"        interface: \"{params.get('interface', 'ethernet1/1')}\"",
            f"        auth_profile: \"{params.get('auth_profile', 'None')}\"",
            f"        vsys: \"{vsys}\""
        ]
        return "\n".join(lines)

    @staticmethod
    def generate_auth_profile_playbook(params: dict) -> str:
        """
        Genera playbook para panos_authentication_profile.
        """
        name = params.get("name", "LDAP-Auth")
        
        lines = [
            "---",
            f"- name: Configurar Perfil de Autenticación - {name}",
            "  hosts: all",
            "  connection: local",
            "  gather_facts: false",
            "  vars:",
            "    provider:",
            "      ip_address: \"{{ device_ip }}\"",
            "      username: \"{{ device_user }}\"",
            "      password: \"{{ device_pass }}\"",
            "  tasks:",
            "    - name: Asegurar Perfil de Auth",
            "      paloaltonetworks.panos.panos_authentication_profile:",
            "        provider: \"{{ provider }}\"",
            f"        name: \"{name}\"",
            f"        type: \"{params.get('type', 'ldap')}\"",
            f"        server_profile: \"{params.get('server_profile', 'None')}\""
        ]
        return "\n".join(lines)
