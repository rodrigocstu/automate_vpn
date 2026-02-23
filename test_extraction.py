#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests exhaustivos para extract_ips_cleaned() y extract_ports_cleaned()
Ejecutar:  python test_extraction.py
"""

from vpn_globalprotect import extract_ips_cleaned, extract_ports_cleaned

# ═══════════════════════════════════════════════════════════════════════
#  IP TESTS — Cada test: (nombre, input, IPs esperadas ya ordenadas)
# ═══════════════════════════════════════════════════════════════════════

IP_TESTS = [
    # ── 1) IP sola con separadores variados ──
    ("1a  IP sola",                  "10.1.2.3",                                  ["10.1.2.3"]),
    ("1b  Comas",                    "10.1.2.3,192.168.1.1",                      ["10.1.2.3", "192.168.1.1"]),
    ("1c  Punto y coma",            "10.1.2.3 ; 192.168.1.1",                    ["10.1.2.3", "192.168.1.1"]),
    ("1d  Pipe",                     "10.1.2.3 | 192.168.1.1",                    ["10.1.2.3", "192.168.1.1"]),
    ("1e  Espacios/tabs/newlines",   "10.1.2.3  \t  192.168.1.1\n172.16.0.1",    ["10.1.2.3", "172.16.0.1", "192.168.1.1"]),
    ("1f  Separadores repetidos",    "10.1.2.3;;;... 192.168.1.1",                ["10.1.2.3", "192.168.1.1"]),

    # ── 2) Envoltura de caracteres ──
    ("2a  Comillas dobles",  '"10.1.2.3"',              ["10.1.2.3"]),
    ("2b  Comillas simples", "'10.1.2.3'",              ["10.1.2.3"]),
    ("2c  Paréntesis",       "(10.1.2.3)",              ["10.1.2.3"]),
    ("2d  Corchetes",        "[10.1.2.3]",              ["10.1.2.3"]),
    ("2e  Llaves",           "{10.1.2.3}",              ["10.1.2.3"]),
    ("2f  Punto final",      "10.1.2.3.",               ["10.1.2.3"]),
    ("2g  Puntos repetidos", "10.1.2.3...",             ["10.1.2.3"]),
    ("2h  Cierre pegado",    "10.1.2.3) y ]172.16.0.1", ["10.1.2.3", "172.16.0.1"]),

    # ── 3) Clave=valor ──
    ("3a  dst=IP",           "dst=10.1.2.3",                  ["10.1.2.3"]),
    ("3b  dst_ip:IP",        'dst_ip:"10.1.2.3"',             ["10.1.2.3"]),
    ("3c  destination-ip",   "destination-ip=10.1.2.3",        ["10.1.2.3"]),
    ("3d  JSON",             '{"dst":"10.1.2.3","port":443}',  ["10.1.2.3"]),

    # ── 4) IP con puerto ──
    ("4a  IP:puerto",    "10.1.2.3:443",       ["10.1.2.3"]),
    ("4b  IP/puerto",    "10.1.2.3/443",       ["10.1.2.3"]),
    ("4c  IP port 443",  "10.1.2.3 port 443",  ["10.1.2.3"]),
    ("4d  IP p=443",     "10.1.2.3 p=443",     ["10.1.2.3"]),

    # ── 5) IP + protocolo + puerto ──
    ("5a  IP tcp/443",       "10.1.2.3 tcp/443",     ["10.1.2.3"]),
    ("5b  IP UDP:53",        "10.1.2.3 UDP:53",      ["10.1.2.3"]),
    ("5c  tcp/443 IP",       "tcp/443 10.1.2.3",     ["10.1.2.3"]),
    ("5d  udp/1900@IP",      "udp/1900@10.1.2.3",    ["10.1.2.3"]),
    ("5e  tcp:80@IP",        "tcp:80@10.1.2.3",      ["10.1.2.3"]),
    ("5f  IP.tcp:443",       "10.1.2.3.tcp:443",     ["10.1.2.3"]),

    # ── 6) URL embebida ──
    ("6a  https://IP/login",    "https://10.1.2.3/login",       ["10.1.2.3"]),
    ("6b  http://IP:8080",      "http://10.1.2.3:8080/path",    ["10.1.2.3"]),
    ("6c  IP:8443/api/v1",      "10.1.2.3:8443/api/v1",         ["10.1.2.3"]),

    # ── 7) CIDR ──
    ("7a  IP/24", "10.1.2.0/24", ["10.1.2.0"]),
    ("7b  IP/32", "10.1.2.3/32", ["10.1.2.3"]),

    # ── 8) Dedup ──
    ("8a  Duplicados", "10.1.2.3 ; 10.1.2.3 ; 192.168.1.1 ; 10.1.2.3", ["10.1.2.3", "192.168.1.1"]),

    # ── 9) Falsos positivos ──
    ("9a  Octetos > 255",  "999.999.999.999", []),
    ("9b  Solo 3 octetos", "10.1.2",          []),
    ("9c  Vacío",          "",                 []),
    ("9d  Sin IPs",        "texto sin ip",    []),
    ("9e  Octeto 256",     "256.1.2.3",        []),

    # ── 10) Orden ──
    ("10a Orden numérico", "192.168.1.10 ; 10.0.0.1 ; 192.168.1.2",
     ["10.0.0.1", "192.168.1.2", "192.168.1.10"]),

    # ── 11) Mega-test ──
    ("11  Mega-input IPs",
     '''dst_ip=10.12.34.56 ; "192.168.1.10".. (172.16.5.200);;;
        https://10.0.0.254/dashboard  {"host":"8.8.8.8"}
        1.1.1.1:53  tcp:80@203.0.113.45  udp/1900@198.51.100.77
        10.99.88.77.tcp:443  destination-ip=192.0.2.99
        10.1.2.0/24  192.168.0.1/32  [172.17.18.19]  '100.64.12.34'
        9.9.9.9 p=5353  999.999.999.999''',
     ["1.1.1.1", "8.8.8.8", "9.9.9.9", "10.0.0.254", "10.1.2.0",
      "10.12.34.56", "10.99.88.77", "100.64.12.34", "172.16.5.200",
      "172.17.18.19", "192.0.2.99", "192.168.0.1", "192.168.1.10",
      "198.51.100.77", "203.0.113.45"]),
]


# ═══════════════════════════════════════════════════════════════════════
#  PORT TESTS — Cada test: (nombre, input, puertos esperados ordenados)
# ═══════════════════════════════════════════════════════════════════════

PORT_TESTS = [
    # ── 1) Puerto solo con ruido ──
    ("P1a  Puerto solo",              "443",                   ["443/TCP"]),
    ("P1b  Puerto con ;;;",           "443 ;;;",               ["443/TCP"]),
    ("P1c  Paréntesis",               "(443)",                 ["443/TCP"]),
    ("P1d  Corchetes",                "[443]",                 ["443/TCP"]),
    ("P1e  Llaves",                   "{443}",                 ["443/TCP"]),
    ("P1f  Lista comas",              "443,80,22",             ["22/TCP", "80/TCP", "443/TCP"]),
    ("P1g  Punto pegado",             "443. 80...",            ["80/TCP", "443/TCP"]),

    # ── 2) Protocolo + puerto ──
    ("P2a  tcp/443",        "tcp/443",        ["443/TCP"]),
    ("P2b  udp/53",         "udp/53",         ["53/UDP"]),
    ("P2c  TCP:443",        "TCP:443",        ["443/TCP"]),
    ("P2d  udp-500",        "udp-500",        ["500/UDP"]),
    ("P2e  tcp 443",        "tcp 443",        ["443/TCP"]),
    ("P2f  tcp=443",        "tcp=443",        ["443/TCP"]),
    ("P2g  udp=53",         "udp=53",         ["53/UDP"]),

    # ── 3) Puerto + protocolo (inverso) ──
    ("P3a  443/tcp",        "443/tcp",        ["443/TCP"]),
    ("P3b  53/udp",         "53/udp",         ["53/UDP"]),
    ("P3c  443 tcp",        "443 tcp",        ["443/TCP"]),
    ("P3d  443-tcp",        "443-tcp",        ["443/TCP"]),

    # ── 4) Clave/valor de logs ──
    ("P4a  dport=443",              "dport=443",                 ["443/TCP"]),
    ("P4b  dst_port:53",            "dst_port:53",               ["53/TCP"]),
    ("P4c  dst-port=500",           "dst-port=500",              ["500/TCP"]),
    ("P4d  destinationPort=3389",   "destinationPort=3389",      ["3389/TCP"]),
    ("P4e  dp=443",                 "dp=443",                    ["443/TCP"]),
    ("P4f  proto=tcp dport=443",    "proto=tcp dport=443",       ["443/TCP"]),
    ("P4g  dst_port=53",            "protocol=udp dst_port=53",  ["53/UDP"]),

    # ── 5) Puerto pegado a IP ──
    ("P5a  IP:443",            "10.1.2.3:443",        ["443/TCP"]),
    ("P5b  IP/443",            "10.1.2.3/443",        ["443/TCP"]),
    ("P5c  IP port 443",       "10.1.2.3 port 443",   ["443/TCP"]),
    ("P5d  tcp/443@IP",        "tcp/443@10.1.2.3",    ["443/TCP"]),
    ("P5e  IP.tcp:443",        "10.1.2.3.tcp:443",    ["443/TCP"]),

    # ── 6) URL embebida ──
    ("P6a  http://IP:8080",    "http://10.1.2.3:8080/path",    ["8080/TCP"]),
    ("P6b  https://IP:443",    "https://1.2.3.4:443/",         ["443/TCP"]),
    ("P6c  ssh://IP:22",       "ssh://10.0.0.5:22",            ["22/TCP"]),

    # ── 7) Rangos ──
    ("P7a  tcp/80-82",
     "tcp/80-82",
     ["80/TCP", "81/TCP", "82/TCP"]),
    ("P7b  udp 500-502",
     "udp 500-502",
     ["500/UDP", "501/UDP", "502/UDP"]),

    # ── 8) Nombres de servicio con puerto ──
    ("P8a  https(443/tcp)",   "https(443/tcp)",    ["443/TCP"]),
    ("P8b  dns 53/udp",       "dns 53/udp",        ["53/UDP"]),
    ("P8c  ssh=22/tcp",       "ssh=22/tcp",        ["22/TCP"]),
    ("P8d  ntp:123/udp",      "ntp:123/udp",       ["123/UDP"]),

    # ── 9) Dedup ──
    ("P9a  Duplicados",
     "tcp/443 ; 443/tcp ; dport=443",
     ["443/TCP"]),

    # ── 10) Falsos positivos ──
    ("P10a Vacío",           "",                    []),
    ("P10b Sin puertos",     "hola mundo",          []),
    ("P10c Puerto > 65535",  "tcp/99999",           []),

    # ── 11) Ordenamiento ──
    ("P11a Orden numérico",
     "tcp/3389, udp/53, tcp/443, tcp/22, tcp/80",
     ["22/TCP", "53/UDP", "80/TCP", "443/TCP", "3389/TCP"]),

    # ── 12) MEGA-TEST ──
    ("P12  Mega-input puertos",
     '''dport=3389 ; dst_port:53 ; tcp/443 ; 80/tcp ; udp-500
        10.1.2.3:8080 ; https://1.2.3.4:8443/api
        tcp:80@10.1.2.3 ; 10.1.2.3.tcp:9090
        ssh=22/tcp ; ntp:123/udp ; dns 53/udp
        port 1433 ; dp=445 ; 443 tcp
        destinationPort=5900''',
     ["22/TCP", "53/TCP", "53/UDP", "80/TCP", "123/UDP", "443/TCP",
      "445/TCP", "500/UDP", "1433/TCP", "3389/TCP", "5900/TCP",
      "8080/TCP", "8443/TCP", "9090/TCP"]),
]


# ═══════════════════════════════════════════════════════════════════════
#  Runner
# ═══════════════════════════════════════════════════════════════════════

def _run_suite(suite_name, tests, extract_fn):
    passed = 0
    failed = 0
    total = len(tests)

    print("=" * 70)
    print(f"  TEST SUITE — {suite_name}")
    print("=" * 70)

    for name, input_text, expected in tests:
        result = extract_fn(input_text)
        ok = result == expected
        icon = "✅" if ok else "❌"
        print(f"\n{icon}  {name}")

        if not ok:
            failed += 1
            print(f"     INPUT:    {repr(input_text[:120])}")
            print(f"     ESPERADO: {expected}")
            print(f"     OBTENIDO: {result}")
            missing = [x for x in expected if x not in result]
            extra = [x for x in result if x not in expected]
            if missing:
                print(f"     FALTAN:   {missing}")
            if extra:
                print(f"     SOBRAN:   {extra}")
        else:
            passed += 1

    print("\n" + "=" * 70)
    print(f"  {suite_name}: {passed}/{total} pasaron   |   {failed} fallaron")
    print("=" * 70)
    return failed == 0


def run_tests():
    ok_ips = _run_suite("extract_ips_cleaned()", IP_TESTS, extract_ips_cleaned)
    print("\n")
    ok_ports = _run_suite("extract_ports_cleaned()", PORT_TESTS, extract_ports_cleaned)

    print("\n" + "═" * 70)
    total = len(IP_TESTS) + len(PORT_TESTS)
    total_pass = sum(1 for *_, e in IP_TESTS + PORT_TESTS
                     if True)  # placeholder
    if ok_ips and ok_ports:
        print(f"  ✅ TOTAL: {total}/{total} tests pasaron")
    else:
        print(f"  ❌ Hay tests fallidos — revisar arriba")
    print("═" * 70)

    return ok_ips and ok_ports


if __name__ == "__main__":
    success = run_tests()
    exit(0 if success else 1)
