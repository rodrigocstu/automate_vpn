import sys
import os

# Agregar directorio actual al path para importar vpn_globalprotect
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from vpn_globalprotect import parse_ticket

def test_parser():
    samples = [
        {
            "name": "Ticket con ruido y separadores",
            "text": """
                REQUERIMIENTO : RITM001234567
                MINSAL == 1234567-89
                RUT -> 12.345.678-9
                TIPO : EXT
                VENCE: 2026-12-31
                IPS: 10.0.0.1, 10.0.0.2; 10.0.0.3
                PUERTOS: [80, 443]
            """,
            "expected": ["ritm", "minsal", "rut", "tipo", "vencimiento", "ips", "puertos"]
        },
        {
            "name": "Ticket multi-línea y sinónimos",
            "text": """
                Solicitud
                RITM009876543
                Contratante:
                Hospital San Juan de Dios
                RUT:
                99.888.777-6
                Vigencia
                2027-01-01
                Hosts
                192.168.1.1 192.168.1.2
            """,
            "expected": ["ritm", "rut", "vencimiento", "ips"]
        },
        {
            "name": "Valores huérfanos (sin etiquetas claras)",
            "text": """
                Hola, necesito acceso para 15.667.889-K. 
                IP: 172.16.0.50 y 172.16.0.51. 
                Vence el 2026-05-20.
                RITM005544332
            """,
            "expected": ["ritm", "rut", "vencimiento", "ips"]
        },
        {
            "name": "Inferencia de Tipo (Fecha -> EXT)",
            "text": """
                RITM: 2602-0727
                Nombre: CARMEN PEREZ
                Vencimiento: 2027-02-19
                Minsal: 0806819-100
                RUT: 16.047.873-K
                IPs: 10.6.68.227
            """,
            "expected": ["ritm", "rut", "tipo", "vencimiento"]
        }
    ]

    print("="*60)
    print("  VERIFICACIÓN DEL PARSER DE TICKETS")
    print("="*60)

    for sample in samples:
        print(f"\n--- Test: {sample['name']} ---")
        result = parse_ticket(sample['text'])
        print(f"Resultado: {result}")
        
        missing = []
        for key in sample['expected']:
            if key not in result or not result[key]:
                missing.append(key)
        
        if not missing:
            print("✅ OK")
        else:
            print(f"❌ FALTAN: {missing}")

if __name__ == "__main__":
    test_parser()
