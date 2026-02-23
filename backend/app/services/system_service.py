class SystemService:
    @staticmethod
    def generate_system_playbook(params: dict) -> str:
        """
        Genera playbook para operaciones de sistema (Commit, Checkpoint).
        """
        vsys = params.get("vsys", "vsys1")
        lines = [
            "---",
            "- name: Operaciones de Sistema PAN-OS",
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

        # Checkpoint (Save before change)
        if params.get("create_checkpoint"):
            lines.append(f"    - name: Crear Checkpoint - {params['checkpoint_name']}")
            lines.append("      paloaltonetworks.panos.panos_checkpoint:")
            lines.append("        provider: \"{{ provider }}\"")
            lines.append(f"        save_name: \"{params['checkpoint_name']}\"")
            lines.append("")

        # Commit
        if params.get("commit"):
            lines.append("    - name: Commitear Cambios")
            lines.append("      paloaltonetworks.panos.panos_commit_firewall:")
            lines.append("        provider: \"{{ provider }}\"")
            lines.append("")

        # Type CMD (Audit/Show)
        if params.get("type_cmd"):
            lines.append(f"    - name: Ejecutar Comando XML - {params['type_cmd']['name']}")
            lines.append("      paloaltonetworks.panos.panos_type_cmd:")
            lines.append("        provider: \"{{ provider }}\"")
            lines.append(f"        xpath: \"{params['type_cmd']['xpath']}\"")
            if params['type_cmd'].get("element"):
                lines.append(f"        element: \"{params['type_cmd']['element']}\"")
            lines.append("")

        return "\n".join(lines)
