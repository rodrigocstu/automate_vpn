import json
from ..core.panos_utils import PanosUtils

class AccessService:
    @staticmethod
    def generate_playbook(params: dict) -> str:
        """
        Genera el contenido YAML del playbook para configuración de acceso.
        Inherited logic from vpn_globalprotect.py
        """
        ritm = params.get("ritm", "RITM_UNKNOWN")
        username = params.get("username", "user_unknown")
        vsys = params.get("vsys", "vsys1")
        tipo = params.get("tipo", "INT").upper()
        
        lines = []
        lines.append("---")
        lines.append(f"- name: Configurar Acceso VPN - {ritm}")
        lines.append("  hosts: all")
        lines.append("  connection: local")
        lines.append("  gather_facts: false")
        lines.append("")
        lines.append("  vars:")
        lines.append("    provider:")
        lines.append("      ip_address: \"{{ device_ip }}\"")
        lines.append("      username: \"{{ device_user }}\"")
        lines.append("      password: \"{{ device_pass }}\"")
        lines.append("")
        lines.append("  tasks:")
        
        # Tarea 1: Asegurar el grupo de usuarios (INT o EXT)
        grupo = params.get("grupo_int", "TIC_MINSAL_INT") if tipo == "INT" else params.get("grupo_ext", "TIC_MINSAL_EXT")
            
        lines.append(f"    - name: Asegurar Usuario en Grupo {grupo}")
        lines.append("      paloaltonetworks.panos.panos_type_cmd:")
        lines.append("        provider: \"{{ provider }}\"")
        lines.append(f"        xpath: \"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{vsys}']/external-list/entry[@name='{grupo}']\"")
        lines.append(f"        element: \"<member>{username}</member>\"")
        lines.append("")

        if tipo == "EXT":
            # Objetos de Dirección
            if params.get("crear_objetos") and params.get("ips"):
                for ip in params["ips"]:
                    obj_name = PanosUtils.build_address_object_name(ip)
                    lines.append(f"    - name: Crear Address Object - {obj_name}")
                    lines.append("      paloaltonetworks.panos.panos_address_object:")
                    lines.append("        provider: \"{{ provider }}\"")
                    lines.append(f"        name: \"{obj_name}\"")
                    lines.append(f"        value: \"{ip}\"")
                    lines.append(f"        vsys: \"{vsys}\"")
                    lines.append("")

            # Objetos de Servicio
            if params.get("crear_objetos") and params.get("puertos"):
                for p_spec in params["puertos"]:
                    svc_name = PanosUtils.build_service_object_name(p_spec)
                    p_val, p_proto = PanosUtils.parse_port_spec(p_spec)
                    lines.append(f"    - name: Crear Service Object - {svc_name}")
                    lines.append("      paloaltonetworks.panos.panos_service_object:")
                    lines.append("        provider: \"{{ provider }}\"")
                    lines.append(f"        name: \"{svc_name}\"")
                    lines.append(f"        protocol: \"{p_proto}\"")
                    lines.append(f"        destination_port: \"{p_val}\"")
                    lines.append(f"        vsys: \"{vsys}\"")
                    lines.append("")

            # Regla de Seguridad
            lines.append(f"    - name: Crear Regla de Seguridad para {ritm}")
            lines.append("      paloaltonetworks.panos.panos_security_rule:")
            lines.append("        provider: \"{{ provider }}\"")
            lines.append(f"        rule_name: \"GP_{ritm}\"")
            lines.append(f"        source_zone: [\"{params.get('zona_origen', 'GP_VPN')}\"]")
            lines.append(f"        destination_zone: [\"{params.get('zona_destino', 'inside_VPN')}\"]")
            lines.append(f"        source_ip: [\"any\"]")
            lines.append(f"        destination_ip: {json.dumps([PanosUtils.build_address_object_name(ip) for ip in params.get('ips', [])]) if params.get('ips') else '[\"any\"]'}")
            lines.append(f"        service: {json.dumps([PanosUtils.build_service_object_name(p) for p in params.get('puertos', [])]) if params.get('puertos') else '[\"service-default\"]'}")
            lines.append(f"        action: \"allow\"")
            lines.append(f"        vsys: \"{vsys}\"")
            lines.append("")

        # Commit opcional
        if params.get("incluir_commit"):
            lines.append("    - name: Commit Changes")
            lines.append("      paloaltonetworks.panos.panos_commit_firewall:")
            lines.append("        provider: \"{{ provider }}\"")
            lines.append("")

        return "\n".join(lines)
