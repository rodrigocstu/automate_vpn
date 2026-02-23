import re

class PanosUtils:
    @staticmethod
    def build_address_object_name(ip: str) -> str:
        """Convención de nombres para address objects: <IP>_32"""
        return f"{ip}_32"

    @staticmethod
    def build_service_object_name(port_spec: str) -> str:
        """Convención de nombres para service objects: <PUERTO>_<PROTO>"""
        p_val, p_proto = PanosUtils.parse_port_spec(port_spec)
        return f"{p_val}_{p_proto.upper()}"

    @staticmethod
    def parse_port_spec(port_spec: str) -> tuple:
        """Parsea '3389/TCP' → ('3389', 'tcp')"""
        if '/' in port_spec:
            parts = port_spec.split('/')
            return parts[0], parts[1].lower()
        elif '_' in port_spec:
            parts = port_spec.split('_')
            return parts[0], parts[1].lower()
        return port_spec, "tcp"
