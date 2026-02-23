# Knowledge Base: Automatización PAN-OS con Ansible

Esta guía contiene información técnica detallada sobre la colección `paloaltonetworks.panos` para su uso en herramientas de IA como NotebookLM. Basada en la documentación oficial de [Ansible Galaxy](https://galaxy.ansible.com/ui/repo/published/paloaltonetworks/panos/) y los repositorios de [Palo Alto Networks](https://github.com/PaloAltoNetworks/ansible-playbooks).

## Estructura de Automatización Profesional (Basada en GitHub)
Los playbooks oficiales de Palo Alto Networks suelen seguir una estructura modular:
- **Playbooks**: Archivos `.yml` específicos por tarea (ej. `add_rule.yml`).
- **Roles**: Bloques reutilizables para configuraciones base (Baseline, Networking, VPN).
- **Inventarios**: Separación de variables de entorno (QA vs PRD).
- **Vars**: Uso extensivo de archivos de variables para evitar hardcoding.

## Categorías de Tareas Automatizadas

### 1. Gestión de Acceso (Access)
- **`panos_global_protect_portal`**: Configuración del portal de entrada.
- **`panos_global_protect_gateway`**: Configuración de túneles y pools IP.
- **`panos_authentication_profile`**: Vinculación con LDAP/RADIUS/SAML.

### 2. Políticas de Seguridad (Policy)
- **`panos_security_rule`**: Gestión de reglas. Los repositorios oficiales recomiendan el uso de `location: top` para reglas críticas.
- **`panos_security_rule_hierarchy`**: Gestión de reglas en Panorama (Device Groups).

### 3. Gestión de Entidades (Entity)
- **`panos_address_object`**: Creación de objetos individuales.
- **`panos_address_group`**: Agrupación lógica de objetos para reglas dinámicas.
- **`panos_service_object`**: Definición de servicios (puertos personalizados).

### 4. Operaciones de Sistema (System)
- **`panos_commit_firewall`**: Aplicación de configuración candidato.
- **`panos_type_cmd`**: Comandos operativos (Show/Config) vía API XML.
- **`panos_checkpoint`**: Creación de versiones de restauración.

## Ejemplo de Playbook Modular
```yaml
- name: Provisión de Acceso VPN
  hosts: firewall
  connection: local
  gather_facts: false
  tasks:
    - name: "Cargar Variables de Ticket"
      include_vars: "vars/ritm12345.yml"

    - name: "Crear Objeto y Regla"
      import_role:
        name: panos_rule_generator
      vars:
        rule_name: "{{ ticket.ritm }}_Access"
        target_ip: "{{ ticket.ip_dest }}"

    - name: "Commit"
      paloaltonetworks.panos.panos_commit_firewall:
        provider: "{{ provider }}"
```

## Módulos Avanzados (Expert Level)

### 5. Networking y Ruteo
- **`panos_interface`**: Gestión de interfaces físicas y lógicas. Crucial para automatizar el aprovisionamiento de nuevas zonas.
- **`panos_static_route`**: Inyección de rutas en Virtual Routers. Los playbooks oficiales suelen usar `next_hop` y `destination` como variables críticas.
- **`panos_zone`**: Definición de zonas de seguridad. Recomendado: Agrupar `interface` y `zone` en un mismo playbook de "Infraestructura".

### 6. NAT y Transformación de Tráfico
- **`panos_nat_rule`**: Gestión de reglas NAT (Source/Destination).
    - **Source NAT**: Comúnmente usado para acceso a Internet vía `dynamic-ip-and-port`.
    - **Destination NAT**: Usado para publicación de servidores (Port Forwarding).
    - **Patrón GitHub**: Definir `snat_type` y `dnat_address` de forma explícita para evitar ambigüedades.

### 7. Gestión de Usuarios y App-ID
- **`panos_userid`**: Interacción con agentes de User-ID. Permite mapear IPs a usuarios de AD.
- **`panos_application_filter`**: Creación de filtros de aplicaciones basados en categorías (ej. `media`, `social-networking`).

## Patrones de Diseño Recomendados por Palo Alto Networks

| Escenario | Estrategia Ansible | Módulos Sugeridos |
| :--- | :--- | :--- |
| **Despliegue Inicial** | Baseline Playbook | Interfaces, Zones, VRs, Management. |
| **Ticketing RITM** | On-demand Access | Address Object + Security Rule. |
| **Migración de Reglas** | Bulk Import | `panos_type_cmd` para set de comandos masivos XML. |
| **Publicación Apps** | Server Publishing | Service Object + NAT Rule + Rule. |

## Mejores Prácticas de Repositorios Oficiales (Actualizado)
1. **Atomaticidad**: Agrupar la creación de objetos y reglas en un solo flujo lógico.
2. **Uso de Tags**: Etiquetar reglas para identificar que fueron creadas por automatización.
3. **Idempotencia**: Confiar en Ansible para no recrear objetos que ya existen idénticos.
4. **Seguridad**: Nunca guardar contraseñas en texto plano; usar `ansible-vault` o variables de entorno.
5. **Check Mode Pre-Commit**: Siempre usar `check_mode: yes` en ejecuciones automáticas antes de un commit oficial.
6. **Device Group vs Firewall**: En Panorama, usar siempre el módulo específico con `device_group` para asegurar la herencia de políticas.
