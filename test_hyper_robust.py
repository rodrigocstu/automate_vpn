from vpn_globalprotect import parse_ticket
import json

ticket_crazy = """
considera esta inteligencia para "tickets" aca va:<<END>>??%%%//...:::;;;...|||...{[()]}}...,""..  %%>>  <<<RITM>>> ???  R I T M 0 0 0 0 1 3 5 9 4 0 7  ;;;  <<<TICKET>>> ???

{Requerimiento :: 2 6 0 2 - 0 7 2 7 } ### ..  Región = Región del Bio Bio ;; Provincia : ( Concepción ) || Comuna [ Talcahuano ] ... ;;; Numero Minsal : 0 8 0 6 8 1 9 - 1 0 0

Nombre_Hospital >>>  " Hospital  Las  Higueras  -  Talcahuano "  .. Dirección = Alto  Horno  N°  7 7 7  ;;;  Contratante :: S . S .  Talcahuano | 6 1 6 0 7 2 0 0 - 5  ... { ] } ( (

[ Acción ] ::: C r e a r  ; Seguridad : V P N  ;;;  Descripción ->  " Crear  VPN  para  Carmen  Perez "  ...  ;;;

--- Datos  Solicitante !!! ---  Nombre  Completo :  Patricio  Alveal  ;; Rut : 1 2 9 9 4 4 9 6 - k  ..  Establecimiento :  Direccion  Servicio  de  Salud  Talcahuano  ;;;  Telefono : 9 5 2 1 9 7 2 8 3  ;; Cargo :  Gestor  ;; Email = patricio.alveal@redsalud.gob.cl  ... ||| ::: ;;; ...

--- Datos  Beneficiarios ??? ---  Nombre  Completo :::  CARMEN  PEREZ  ;; Rut = 1 6 0 4 7 8 7 3 - K  ..  Establecimiento = " Hospital  Las  higueras "  ;;;  Telefono : 9 9 4 4 2 2 9 9 7  ;; Cargo = medico ;; Email { caranguizb@gmail.com } ... Fecha  de  Expiracion => 2 0 2 7 - 0 2 - 1 9 ;;;;

Listado  de  IP  a  Acceder :  1 0  .  6 8  .  1 3 6  .  3 2   ..   1 0  .  6 8  .  1 3 6  .  3 1  |||  1 0  .  6 8  .  1 3 6  .  3 0  ;;;  1 0  .  6  .  6 8  .  2 2 7  ....  Puertos ::: [ 3 3 8 9 ]  ;;;  <<<<< 3 3 8 9 >>>>>

Observación ::: " INFORME  A  DISTANCIA  DE  EEG  EN  CASOS  DE  MUERTE  ENCEFALICA , VIDEO  MONITOREO  DE  EEG  EN  PACIENTES  UPC ,  ESTUDIOS  PREQUIRURGICOS " ...;;;;  ( Region ) Región del Bio Bio :: ( Provincia ) Concepción :: ( Comuna ) Talcahuano ;;;

%%%//<<END>>??<<<RITM>>>...,,,;;;:::|||..."Hospital Las higueras"...patricio.alveal@redsalud.gob.cl...caranguizb@gmail.com... 1 2 9 9 4 4 9 6 - k ... 1 6 0 4 7 8 7 3 - K ... 9 5 2 1 9 7 2 8 3 ... 9 9 4 4 2 2 9 9 7 ... Alto Horno N° 7 7 7 ... S.S. Talcahuano ... Direccion Servicio de Salud Talcahuano ..."
"""

def test():
    print("="*60)
    print("  VERIFICACIÓN HIPER-ROBUSTA (TICKET EXTREMO)")
    print("="*60)
    
    parsed = parse_ticket(ticket_crazy)
    
    # Verificaciones clave
    expected_fields = {
        "ritm": "RITM00001359407",
        "minsal": "0806819-100",
        "rut": "16047873-k",
        "vencimiento": "2027-02-19",
        "nombre": "CARMEN PEREZ",
        "email": "caranguizb@gmail.com",
        "tipo": "EXT"
    }
    
    all_ok = True
    for field, expected in expected_fields.items():
        val = parsed.get(field)
        if val == expected:
            print(f"✅ {field.upper()}: {val}")
        else:
            print(f"❌ {field.upper()}: Esperado '{expected}', obtenido '{val}'")
            all_ok = False
            
    # IPs
    expected_ips = ["10.6.68.227", "10.68.136.30", "10.68.136.31", "10.68.136.32"]
    if sorted(parsed.get("ips", [])) == expected_ips:
        print(f"✅ IPs: {parsed['ips']}")
    else:
        print(f"❌ IPs: Obtenido {parsed.get('ips')}")
        all_ok = False
        
    # Puertos
    if any("3389" in p for p in parsed.get("puertos", [])):
        print(f"✅ Puerto: 3389 detectado")
    else:
        print(f"❌ Puerto: 3389 NO detectado (obtenido: {parsed.get('puertos')})")
        all_ok = False

    print("\nRESULTADO FINAL:", "PASÓ ✅" if all_ok else "FALLÓ ❌")

if __name__ == "__main__":
    test()
