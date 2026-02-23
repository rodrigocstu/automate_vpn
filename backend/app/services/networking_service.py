from ..core.panos_utils import PanosUtils

class NetworkingService:
    @staticmethod
    def generate_interface_playbook(params: dict) -> str:
        """
        Genera playbook para panos_interface y panos_zone.
        """
        firewall_ip = params.get("firewall_ip", "1.1.1.1")
        if_name = params.get("interface_name", "ethernet1/1")
        zone_name = params.get("zone_name", "untrusted")
        mode = params.get("mode", "layer3") # layer3, layer2, etc.
        
        lines = []
        lines.append("---")
        lines.append("- name: Configurar Networking PAN-OS")
        lines.append("  hosts: all")
        lines.append("  connection: local")
        lines.append("  gather_facts: false")
        lines.append("")
        lines.append("  tasks:")
        lines.append(f"    - name: Configurar Interface {if_name}")
        lines.append("      paloaltonetworks.panos.panos_interface:")
        lines.append("        provider: \"{{ provider }}\"")
        lines.append(f"        if_name: \"{if_name}\"")
        lines.append(f"        mode: \"{mode}\"")
        lines.append("        state: 'present'")
        lines.append("")
        lines.append(f"    - name: Asegurar Zona {zone_name}")
        lines.append("      paloaltonetworks.panos.panos_zone:")
        lines.append("        provider: \"{{ provider }}\"")
        lines.append(f"        zone: \"{zone_name}\"")
        lines.append(f"        mode: \"{mode}\"")
        lines.append(f"        interfaces: [\"{if_name}\"]")
        lines.append("        state: 'present'")
        
        return "\n".join(lines)

    @staticmethod
    def generate_static_route_playbook(params: dict) -> str:
        """
        Genera playbook para panos_static_route.
        """
        dest = params.get("destination", "0.0.0.0/0")
        nexthop = params.get("next_hop", "10.0.0.1")
        vr_name = params.get("vr_name", "default")
        
        lines = []
        lines.append("---")
        lines.append("- name: Inyectar Ruta Estática")
        lines.append("  hosts: all")
        lines.append("  connection: local")
        lines.append("  gather_facts: false")
        lines.append("")
        lines.append("  tasks:")
        lines.append(f"    - name: Ruta hacia {dest}")
        lines.append("      paloaltonetworks.panos.panos_static_route:")
        lines.append("        provider: \"{{ provider }}\"")
        lines.append(f"        name: \"Route_{dest.replace('/', '_')}\"")
        lines.append(f"        destination: \"{dest}\"")
        lines.append(f"        nexthop: \"{nexthop}\"")
        lines.append(f"        virtual_router: \"{vr_name}\"")
        lines.append("        state: 'present'")
        
        return "\n".join(lines)
