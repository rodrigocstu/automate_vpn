from ..core.panos_utils import PanosUtils
import json

class PolicyService:
    @staticmethod
    def generate_policy_playbook(params: dict) -> str:
        """
        Genera un playbook para reglas de seguridad y jerarquía.
        """
        vsys = params.get("vsys", "vsys1")
        lines = [
            "---",
            "- name: Gestionar Políticas de Seguridad PAN-OS",
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

        # Tags
        for tag in params.get("tags", []):
            lines.append(f"    - name: Asegurar Tag - {tag['name']}")
            lines.append("      paloaltonetworks.panos.panos_tag:")
            lines.append("        provider: \"{{ provider }}\"")
            lines.append(f"        name: \"{tag['name']}\"")
            lines.append(f"        color: \"{tag.get('color', 'orange')}\"")
            lines.append(f"        vsys: \"{vsys}\"")
            lines.append("")

        # Security Rules
        for rule in params.get("rules", []):
            lines.append(f"    - name: Asegurar Regla - {rule['name']}")
            lines.append("      paloaltonetworks.panos.panos_security_rule:")
            lines.append("        provider: \"{{ provider }}\"")
            lines.append(f"        rule_name: \"{rule['name']}\"")
            lines.append(f"        source_zone: {json.dumps(rule.get('source_zone', ['any']))}")
            lines.append(f"        destination_zone: {json.dumps(rule.get('destination_zone', ['any']))}")
            lines.append(f"        source_ip: {json.dumps(rule.get('source_ip', ['any']))}")
            lines.append(f"        destination_ip: {json.dumps(rule.get('destination_ip', ['any']))}")
            lines.append(f"        service: {json.dumps(rule.get('service', ['service-default']))}")
            lines.append(f"        application: {json.dumps(rule.get('application', ['any']))}")
            lines.append(f"        action: \"{rule.get('action', 'allow')}\"")
            lines.append(f"        vsys: \"{vsys}\"")
            if rule.get("tags"):
                lines.append(f"        tag: {json.dumps(rule['tags'])}")
            lines.append("")

            # Hierarchy (Opcional por regla)
            if rule.get("location"):
                lines.append(f"    - name: Mover Regla - {rule['name']} a {rule['location']}")
                lines.append("      paloaltonetworks.panos.panos_security_rule_hierarchy:")
                lines.append("        provider: \"{{ provider }}\"")
                lines.append(f"        rule_name: \"{rule['name']}\"")
                lines.append(f"        location: \"{rule['location']}\"")
                if rule.get("relative_to"):
                    lines.append(f"        relative_to: \"{rule['relative_to']}\"")
                lines.append(f"        vsys: \"{vsys}\"")
                lines.append("")

        return "\n".join(lines)
