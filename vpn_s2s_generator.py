import argparse
import re

class PAN_S2S_Generator:
    def __init__(self, data):
        self.data = data
        self.cli = []

    def validate_ip(self, ip):
        # Basic CIDR/IP validation
        return re.match(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$", ip)

    def generate(self):
        # 1. Address Objects
        self.cli.append("# --- Address Objects ---")
        self.cli.append(f"set address OBJ_LOCAL_{self.data['local_subnet'].replace('/','-')} ip-netmask {self.data['local_subnet']}")
        self.cli.append(f"set address OBJ_REMOTE_{self.data['remote_subnet'].replace('/','-')} ip-netmask {self.data['remote_subnet']}")
        
        # 2. Crypto Profiles — Dynamic (PAN-OS 10.2.x)
        self.cli.append("\n# --- Crypto Profiles ---")
        ike_enc      = self.data.get('ike_enc',      'aes-256-cbc')
        ike_hash     = self.data.get('ike_hash',     'sha256')
        ike_dh       = self.data.get('ike_dh',       'group14')
        ike_lifetime = self.data.get('ike_lifetime', '8')
        ipsec_enc    = self.data.get('ipsec_enc',    'aes-256-cbc')
        ipsec_auth   = self.data.get('ipsec_auth',   'sha256')
        ipsec_dh     = self.data.get('ipsec_dh',     'group14')
        ipsec_life   = self.data.get('ipsec_lifetime', '1')

        self.cli.append(
            f"set network ike crypto-profiles ike-crypto-profile CP_IKE_PH1 "
            f"hash {ike_hash} encryption {ike_enc} dh-group {ike_dh} lifetime hours {ike_lifetime}"
        )
        # IPsec profile: omit auth if using AEAD (GCM) cipher
        if 'gcm' in ipsec_enc or ipsec_auth == 'none':
            self.cli.append(
                f"set network ipsec crypto-profiles ipsec-crypto-profile CP_IPSEC_PH2 "
                f"esp encryption {ipsec_enc} dh-group {ipsec_dh} lifetime hours {ipsec_life}"
            )
        else:
            self.cli.append(
                f"set network ipsec crypto-profiles ipsec-crypto-profile CP_IPSEC_PH2 "
                f"esp authentication {ipsec_auth} encryption {ipsec_enc} dh-group {ipsec_dh} lifetime hours {ipsec_life}"
            )

        # 3. IKE Gateway
        self.cli.append("\n# --- IKE Gateway ---")
        gw_name = f"GW_S2S_PEER_{self.data['peer_ip']}"
        self.cli.append(f"set network ike gateway {gw_name} protocol ikev2 yes")
        self.cli.append(f"set network ike gateway {gw_name} protocol ikev2 ike-crypto-profile CP_IKE_PH1")
        self.cli.append(f"set network ike gateway {gw_name} protocol version ikev2")
        self.cli.append(f"set network ike gateway {gw_name} authentication pre-shared-key key \"{self.data['psk']}\"")
        self.cli.append(f"set network ike gateway {gw_name} peer-address ip {self.data['peer_ip']}")
        self.cli.append(f"set network ike gateway {gw_name} local-address interface {self.data['local_if']}")
        # Explicit local-address ip — required for multi-IP interfaces and interop with FortiGate
        local_wan_ip = self.data.get('local_wan_ip', '').strip()
        if local_wan_ip:
            self.cli.append(f"set network ike gateway {gw_name} local-address ip {local_wan_ip}")

        # 4. Tunnel Interface
        self.cli.append("\n# --- Tunnel Interface ---")
        tun_id = self.data.get('tunnel_id', '100')
        tun_if = f"tunnel.{tun_id}"
        
        # Custom Zone Logic: MINSAL_TO_ prefix
        raw_zone = self.data.get('tunnel_zone', 'REMOTE_VPN')
        tun_zone = f"MINSAL_TO_{raw_zone}"
        
        self.cli.append(f"set network interface tunnel units {tun_if} virtual-router {self.data['vr']}")
        self.cli.append(f"set network interface tunnel units {tun_if} zone {tun_zone}")

        # 5. IPsec Tunnel
        self.cli.append("\n# --- IPsec Tunnel ---")
        vpn_name = f"VPN_S2S_PEER_{self.data['peer_ip']}"
        self.cli.append(f"set network ipsec tunnel {vpn_name} auto-key ike-gateway {gw_name}")
        self.cli.append(f"set network ipsec tunnel {vpn_name} auto-key ipsec-crypto-profile CP_IPSEC_PH2")
        self.cli.append(f"set network ipsec tunnel {vpn_name} tunnel-interface {tun_if}")

        # 6. Proxy-ID (for Policy-based)
        if self.data['mode'] == 'Proxy-ID':
            self.cli.append(f"set network ipsec tunnel {vpn_name} proxy-id PID_S2S local {self.data['local_subnet']} remote {self.data['remote_subnet']} protocol any")

        # 7. Routing
        self.cli.append("\n# --- Routing ---")
        self.cli.append(f"set network virtual-router {self.data['vr']} routing-table static route ROUTE_TO_PEER destination {self.data['remote_subnet']} interface {tun_if}")


        # 8. Security Policies (App-ID aware — PA-5250 / PAN-OS 10.2.x standard)
        if self.data['create_policies']:
            self.cli.append("\n# --- Security Policies (App-ID based — PA-5250 standards) ---")

            # Resolve app list for the policy
            raw_apps = self.data.get('applications', [])
            if isinstance(raw_apps, str):
                raw_apps = [a.strip() for a in raw_apps.split(',') if a.strip()]

            # Validate against catalog
            try:
                from appid_catalog import APPID_CATALOG
                valid_apps = [a for a in raw_apps if a in APPID_CATALOG]
            except ImportError:
                valid_apps = raw_apps  # fallback — no catalog available

            app_fragment = ("[ " + " ".join(valid_apps) + " ]") if valid_apps else "any"
            svc_fragment = "application-default" if valid_apps else "any"

            rule_suffix = f"_{self.data['peer_ip'].replace('.', '_')}"

            # OUTBOUND: local zone → tunnel zone
            self.cli.append(
                f"set rulebase security rules OUTBOUND_VPN{rule_suffix} "
                f"from {self.data['local_zone']} "
                f"to {tun_zone} "
                f"source OBJ_LOCAL_{self.data['local_subnet'].replace('/','-')} "
                f"destination OBJ_REMOTE_{self.data['remote_subnet'].replace('/','-')} "
                f"application {app_fragment} "
                f"service {svc_fragment} "
                f"action allow "
                f"log-end yes "
                f"description \"VPN S2S Outbound - {self.data.get('ritm','S2S')}\""
            )

            # INBOUND: tunnel zone → local zone
            self.cli.append(
                f"set rulebase security rules INBOUND_VPN{rule_suffix} "
                f"from {tun_zone} "
                f"to {self.data['local_zone']} "
                f"source OBJ_REMOTE_{self.data['remote_subnet'].replace('/','-')} "
                f"destination OBJ_LOCAL_{self.data['local_subnet'].replace('/','-')} "
                f"application {app_fragment} "
                f"service {svc_fragment} "
                f"action allow "
                f"log-end yes "
                f"description \"VPN S2S Inbound - {self.data.get('ritm','S2S')}\""
            )

            # Deny-all catch-all at bottom of VPN rules (best practice)
            self.cli.append(
                f"set rulebase security rules DENY_VPN{rule_suffix} "
                f"from {self.data['local_zone']} {tun_zone} "
                f"to {self.data['local_zone']} {tun_zone} "
                f"source any destination any "
                f"application any service any "
                f"action deny log-end yes "
                f"description \"VPN catch-all deny — move above broader rules\""
            )

        return "\n".join(self.cli)

if __name__ == "__main__":
    # Final production data for 186.67.71.23
    config_data = {
        'mode': 'Proxy-ID',
        'peer_ip': '200.152.69.125',           # FortiGate peer
        'local_wan_ip': '186.67.71.23',         # Palo Alto WAN IP
        'psk': 'SecureKey2026!',
        'local_subnet': '10.10.0.0/24',
        'remote_subnet': '192.168.100.0/24',
        'local_if': 'ethernet1/2',
        'tunnel_id': '100',
        'tunnel_zone': 'FORTIGATE_POC',         # → MINSAL_TO_FORTIGATE_POC
        'local_zone': 'Inside',
        'vr': 'vr_vpn',
        'create_policies': True,
        'ike_enc': 'aes-256-cbc', 'ike_hash': 'sha256', 'ike_dh': 'group14', 'ike_lifetime': '8',
        'ipsec_enc': 'aes-256-cbc', 'ipsec_auth': 'sha256', 'ipsec_dh': 'group14', 'ipsec_lifetime': '1',
    }
    
    gen = PAN_S2S_Generator(config_data)
    output = gen.generate()
    
    print("#" * 40)
    print("# GENERADOR VPN IPSEC S2S - MINSAL EDITION")
    print("#" * 40)
    print(output)
