from ..core.panos_utils import PanosUtils

class EntityService:
    @staticmethod
    def generate_entity_playbook(params: dict) -> str:
        """
        Genera un playbook que puede contener múltiples objetos de dirección, servicio y grupos.
        """
        vsys = params.get("vsys", "vsys1")
        lines = [
            "---",
            "- name: Gestionar Entidades PAN-OS",
            "  hosts: all",
            "  connection: local",
            "  gather_facts: false",
            "  vars:",
            "    provider:",
            "      ip_address: \"{{ device_ip }}\"",
            "      username: \"{{ device_user }}\"",
            "      password: \"{{ device_pass }}\"",
            "  tasks:"
        ]

        # Address Objects
        for addr in params.get("addresses", []):
            lines.append(f"    - name: Asegurar Address Object - {addr['name']}")
            lines.append("      paloaltonetworks.panos.panos_address_object:")
            lines.append("        provider: \"{{ provider }}\"")
            lines.append(f"        name: \"{addr['name']}\"")
            lines.append(f"        value: \"{addr['value']}\"")
            lines.append(f"        vsys: \"{vsys}\"")
            lines.append("")

        # Service Objects
        for svc in params.get("services", []):
            lines.append(f"    - name: Asegurar Service Object - {svc['name']}")
            lines.append("      paloaltonetworks.panos.panos_service_object:")
            lines.append("        provider: \"{{ provider }}\"")
            lines.append(f"        name: \"{svc['name']}\"")
            lines.append(f"        protocol: \"{svc.get('protocol', 'tcp')}\"")
            lines.append(f"        destination_port: \"{svc['port']}\"")
            lines.append(f"        vsys: \"{vsys}\"")
            lines.append("")

        # Address Groups
        for grp in params.get("address_groups", []):
            lines.append(f"    - name: Asegurar Address Group - {grp['name']}")
            lines.append("      paloaltonetworks.panos.panos_address_group:")
            lines.append("        provider: \"{{ provider }}\"")
            lines.append(f"        name: \"{grp['name']}\"")
            lines.append(f"        static_value: {grp['static_value']}")
            lines.append(f"        vsys: \"{vsys}\"")
            lines.append("")

        return "\n".join(lines)
