from ..core.panos_utils import PanosUtils

class NatService:
    @staticmethod
    def generate_nat_playbook(params: dict) -> str:
        """
        Genera playbook para panos_nat_rule.
        Soporta Source NAT (Dynamic IP and Port) y Destination NAT.
        """
        name = params.get("name", "NAT_Rule_Manual")
        src_zone = params.get("source_zone", "untrusted")
        dest_zone = params.get("destination_zone", "untrusted")
        src_addr = params.get("source_address", ["any"])
        dest_addr = params.get("destination_address", ["any"])
        
        nat_type = params.get("nat_type", "source") # source / destination
        
        lines = []
        lines.append("---")
        lines.append(f"- name: Configurar NAT - {name}")
        lines.append("  hosts: all")
        lines.append("  connection: local")
        lines.append("  gather_facts: false")
        lines.append("")
        lines.append("  tasks:")
        lines.append(f"    - name: Aplicar Regla NAT {name}")
        lines.append("      paloaltonetworks.panos.panos_nat_rule:")
        lines.append("        provider: \"{{ provider }}\"")
        lines.append(f"        rule_name: \"{name}\"")
        lines.append(f"        source_zone: [\"{src_zone}\"]")
        lines.append(f"        destination_zone: \"{dest_zone}\"")
        lines.append(f"        source_ip: {src_addr}")
        lines.append(f"        destination_ip: {dest_addr}")
        
        if nat_type == "source":
            lines.append("        snat_type: 'dynamic-ip-and-port'")
            lines.append("        snat_interface: \"ethernet1/1\" # Default interface for SNAT")
        elif nat_type == "destination":
            translated_addr = params.get("translated_address", "10.0.0.100")
            lines.append(f"        dnat_address: \"{translated_addr}\"")
            
        lines.append("        state: 'present'")
        
        return "\n".join(lines)
