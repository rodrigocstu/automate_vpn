"""
PAN-OS 10.2.x App-ID Catalog — PA-5250 / PA-5450 / PA-3400 series
Source: Palo Alto Networks Applipedia (applipedia.paloaltonetworks.com)
Last sync: 2026-02 — covers PAN-OS 10.2.16-h6

Usage:
    from appid_catalog import APPID_CATALOG, search_app, COMMON_VPN_APPS
"""

# ---------------------------------------------------------------------------
# Full catalog: {app_id: {name, category, subcategory, risk, transport}}
# ---------------------------------------------------------------------------
APPID_CATALOG = {
    # ── NETWORKING ──────────────────────────────────────────────────────────
    "ping":              {"name":"ICMP Ping",               "category":"networking","subcategory":"ip-protocol","risk":1,"transport":"ICMP"},
    "icmp":              {"name":"ICMP",                    "category":"networking","subcategory":"ip-protocol","risk":1,"transport":"ICMP"},
    "traceroute":        {"name":"Traceroute",              "category":"networking","subcategory":"ip-protocol","risk":1,"transport":"UDP"},
    "dns":               {"name":"DNS",                     "category":"networking","subcategory":"infrastructure","risk":1,"transport":"UDP/TCP"},
    "ntp":               {"name":"NTP",                     "category":"networking","subcategory":"infrastructure","risk":1,"transport":"UDP"},
    "dhcp":              {"name":"DHCP",                    "category":"networking","subcategory":"infrastructure","risk":1,"transport":"UDP"},
    "snmp":              {"name":"SNMP",                    "category":"networking","subcategory":"management","risk":2,"transport":"UDP"},
    "netbios":           {"name":"NetBIOS",                 "category":"networking","subcategory":"infrastructure","risk":2,"transport":"UDP/TCP"},
    "ldap":              {"name":"LDAP",                    "category":"networking","subcategory":"infrastructure","risk":2,"transport":"TCP"},
    "ldap-ssl":          {"name":"LDAP over SSL",           "category":"networking","subcategory":"infrastructure","risk":2,"transport":"TCP"},
    "kerberos":          {"name":"Kerberos",                "category":"networking","subcategory":"authentication","risk":2,"transport":"TCP/UDP"},
    "radius":            {"name":"RADIUS",                  "category":"networking","subcategory":"authentication","risk":2,"transport":"UDP"},
    "tacacs-plus":       {"name":"TACACS+",                 "category":"networking","subcategory":"authentication","risk":2,"transport":"TCP"},
    "ssh":               {"name":"SSH",                     "category":"networking","subcategory":"remote-access","risk":2,"transport":"TCP"},
    "telnet":            {"name":"Telnet",                  "category":"networking","subcategory":"remote-access","risk":4,"transport":"TCP"},
    "ftp":               {"name":"FTP",                     "category":"networking","subcategory":"file-sharing","risk":3,"transport":"TCP"},
    "tftp":              {"name":"TFTP",                    "category":"networking","subcategory":"file-sharing","risk":3,"transport":"UDP"},
    "scp":               {"name":"SCP",                     "category":"networking","subcategory":"file-sharing","risk":2,"transport":"TCP"},
    "sftp":              {"name":"SFTP",                    "category":"networking","subcategory":"file-sharing","risk":2,"transport":"TCP"},
    "nfs":               {"name":"NFS",                     "category":"networking","subcategory":"file-sharing","risk":3,"transport":"TCP/UDP"},
    "samba":             {"name":"SMB/CIFS",                "category":"networking","subcategory":"file-sharing","risk":3,"transport":"TCP"},
    "msrpc":             {"name":"MSRPC",                   "category":"networking","subcategory":"infrastructure","risk":3,"transport":"TCP"},
    "netflow":           {"name":"NetFlow",                 "category":"networking","subcategory":"management","risk":1,"transport":"UDP"},
    "syslog":            {"name":"Syslog",                  "category":"networking","subcategory":"management","risk":1,"transport":"UDP"},
    "bgp":               {"name":"BGP",                     "category":"networking","subcategory":"routing-protocol","risk":2,"transport":"TCP"},
    "ospf":              {"name":"OSPF",                    "category":"networking","subcategory":"routing-protocol","risk":2,"transport":"IP"},
    "eigrp":             {"name":"EIGRP",                   "category":"networking","subcategory":"routing-protocol","risk":2,"transport":"IP"},
    "rip":               {"name":"RIP",                     "category":"networking","subcategory":"routing-protocol","risk":2,"transport":"UDP"},
    "pim":               {"name":"PIM",                     "category":"networking","subcategory":"routing-protocol","risk":1,"transport":"IP"},
    "ipsec-esp":         {"name":"IPsec ESP",               "category":"networking","subcategory":"encrypted-tunnel","risk":2,"transport":"IP"},
    "ike":               {"name":"IKE",                     "category":"networking","subcategory":"encrypted-tunnel","risk":2,"transport":"UDP"},
    "gre":               {"name":"GRE",                     "category":"networking","subcategory":"tunneling","risk":3,"transport":"IP"},
    "l2tp":              {"name":"L2TP",                    "category":"networking","subcategory":"tunneling","risk":3,"transport":"UDP"},
    "pptp":              {"name":"PPTP",                    "category":"networking","subcategory":"tunneling","risk":4,"transport":"TCP"},
    "vxlan":             {"name":"VXLAN",                   "category":"networking","subcategory":"tunneling","risk":2,"transport":"UDP"},
    "ntp-base":          {"name":"NTP Base",                "category":"networking","subcategory":"infrastructure","risk":1,"transport":"UDP"},
    "wins":              {"name":"WINS",                    "category":"networking","subcategory":"infrastructure","risk":2,"transport":"UDP/TCP"},

    # ── WEB ─────────────────────────────────────────────────────────────────
    "web-browsing":      {"name":"Web Browsing (HTTP)",     "category":"general-internet","subcategory":"internet-utility","risk":3,"transport":"TCP"},
    "ssl":               {"name":"SSL/TLS (HTTPS)",         "category":"general-internet","subcategory":"internet-utility","risk":3,"transport":"TCP"},
    "http2":             {"name":"HTTP/2",                  "category":"general-internet","subcategory":"internet-utility","risk":3,"transport":"TCP"},
    "http3":             {"name":"HTTP/3 (QUIC)",           "category":"general-internet","subcategory":"internet-utility","risk":3,"transport":"UDP"},
    "websocket":         {"name":"WebSocket",               "category":"general-internet","subcategory":"internet-utility","risk":3,"transport":"TCP"},
    "quic":              {"name":"QUIC",                    "category":"general-internet","subcategory":"internet-utility","risk":3,"transport":"UDP"},

    # ── EMAIL ────────────────────────────────────────────────────────────────
    "smtp":              {"name":"SMTP",                    "category":"collaboration","subcategory":"email","risk":3,"transport":"TCP"},
    "smtp-ssl":          {"name":"SMTP over SSL",           "category":"collaboration","subcategory":"email","risk":2,"transport":"TCP"},
    "pop3":              {"name":"POP3",                    "category":"collaboration","subcategory":"email","risk":3,"transport":"TCP"},
    "pop3-ssl":          {"name":"POP3 over SSL",           "category":"collaboration","subcategory":"email","risk":2,"transport":"TCP"},
    "imap":              {"name":"IMAP",                    "category":"collaboration","subcategory":"email","risk":3,"transport":"TCP"},
    "imap-ssl":          {"name":"IMAP over SSL",           "category":"collaboration","subcategory":"email","risk":2,"transport":"TCP"},
    "ms-exchange":       {"name":"Microsoft Exchange",      "category":"collaboration","subcategory":"email","risk":2,"transport":"TCP"},
    "outlook-web":       {"name":"Outlook Web Access",      "category":"collaboration","subcategory":"email","risk":2,"transport":"TCP"},

    # ── MICROSOFT 365 / AZURE ────────────────────────────────────────────────
    "ms365":             {"name":"Microsoft 365",           "category":"saas","subcategory":"office-programs","risk":2,"transport":"TCP"},
    "ms365-base":        {"name":"Microsoft 365 Base",      "category":"saas","subcategory":"office-programs","risk":2,"transport":"TCP"},
    "ms365-enterprise":  {"name":"Microsoft 365 Enterprise","category":"saas","subcategory":"office-programs","risk":2,"transport":"TCP"},
    "onedrive":          {"name":"Microsoft OneDrive",      "category":"saas","subcategory":"storage-backup","risk":2,"transport":"TCP"},
    "sharepoint":        {"name":"Microsoft SharePoint",    "category":"saas","subcategory":"collaboration","risk":2,"transport":"TCP"},
    "teams":             {"name":"Microsoft Teams",         "category":"collaboration","subcategory":"internet-conferencing","risk":2,"transport":"TCP/UDP"},
    "ms-lync":           {"name":"Microsoft Lync/Skype",    "category":"collaboration","subcategory":"video-voice","risk":2,"transport":"TCP/UDP"},
    "azure-ad":          {"name":"Azure Active Directory",  "category":"saas","subcategory":"authentication","risk":2,"transport":"TCP"},
    "azure-services":    {"name":"Microsoft Azure Services","category":"saas","subcategory":"cloud","risk":2,"transport":"TCP"},

    # ── DATABASES ────────────────────────────────────────────────────────────
    "mssql":             {"name":"Microsoft SQL Server",    "category":"business-systems","subcategory":"database","risk":3,"transport":"TCP"},
    "mysql":             {"name":"MySQL",                   "category":"business-systems","subcategory":"database","risk":3,"transport":"TCP"},
    "postgresql":        {"name":"PostgreSQL",              "category":"business-systems","subcategory":"database","risk":3,"transport":"TCP"},
    "oracle-db":         {"name":"Oracle Database",         "category":"business-systems","subcategory":"database","risk":3,"transport":"TCP"},
    "mongodb":           {"name":"MongoDB",                 "category":"business-systems","subcategory":"database","risk":3,"transport":"TCP"},
    "redis":             {"name":"Redis",                   "category":"business-systems","subcategory":"database","risk":3,"transport":"TCP"},
    "oracle":            {"name":"Oracle",                  "category":"business-systems","subcategory":"database","risk":3,"transport":"TCP"},
    "ibm-db2":           {"name":"IBM DB2",                 "category":"business-systems","subcategory":"database","risk":3,"transport":"TCP"},

    # ── REMOTE MANAGEMENT ───────────────────────────────────────────────────
    "rdp":               {"name":"Remote Desktop (RDP)",    "category":"networking","subcategory":"remote-access","risk":4,"transport":"TCP"},
    "vnc":               {"name":"VNC",                     "category":"networking","subcategory":"remote-access","risk":4,"transport":"TCP"},
    "teamviewer":        {"name":"TeamViewer",              "category":"networking","subcategory":"remote-access","risk":4,"transport":"TCP/UDP"},
    "anydesk":           {"name":"AnyDesk",                 "category":"networking","subcategory":"remote-access","risk":4,"transport":"TCP/UDP"},
    "citrix":            {"name":"Citrix",                  "category":"networking","subcategory":"remote-access","risk":3,"transport":"TCP"},
    "vmware-view":       {"name":"VMware Horizon View",     "category":"networking","subcategory":"remote-access","risk":3,"transport":"TCP/UDP"},
    "ms-rdp":            {"name":"Microsoft RDP",           "category":"networking","subcategory":"remote-access","risk":4,"transport":"TCP"},

    # ── VOICE / VIDEO CONFERENCING ──────────────────────────────────────────
    "sip":               {"name":"SIP",                     "category":"collaboration","subcategory":"voip-video","risk":3,"transport":"UDP/TCP"},
    "sip-tls":           {"name":"SIP over TLS",            "category":"collaboration","subcategory":"voip-video","risk":2,"transport":"TCP"},
    "h323":              {"name":"H.323",                   "category":"collaboration","subcategory":"voip-video","risk":3,"transport":"TCP/UDP"},
    "rtp":               {"name":"RTP/RTSP",                "category":"collaboration","subcategory":"voip-video","risk":2,"transport":"UDP"},
    "zoom":              {"name":"Zoom",                    "category":"collaboration","subcategory":"internet-conferencing","risk":2,"transport":"TCP/UDP"},
    "webex":             {"name":"Cisco WebEx",             "category":"collaboration","subcategory":"internet-conferencing","risk":2,"transport":"TCP/UDP"},
    "gotomeeting":       {"name":"GoToMeeting",             "category":"collaboration","subcategory":"internet-conferencing","risk":2,"transport":"TCP"},

    # ── MONITORING / MANAGEMENT ─────────────────────────────────────────────
    "snmp-trap":         {"name":"SNMP Trap",               "category":"networking","subcategory":"management","risk":2,"transport":"UDP"},
    "netconf":           {"name":"NETCONF",                 "category":"networking","subcategory":"management","risk":2,"transport":"TCP"},
    "restconf":          {"name":"RESTCONF",                "category":"networking","subcategory":"management","risk":2,"transport":"TCP"},
    "grpc":              {"name":"gRPC",                    "category":"networking","subcategory":"management","risk":2,"transport":"TCP"},
    "zabbix":            {"name":"Zabbix",                  "category":"networking","subcategory":"management","risk":2,"transport":"TCP"},
    "nagios":            {"name":"Nagios",                  "category":"networking","subcategory":"management","risk":2,"transport":"TCP"},
    "prometheus":        {"name":"Prometheus",              "category":"networking","subcategory":"management","risk":2,"transport":"TCP"},

    # ── SECURITY / IDENTITY ─────────────────────────────────────────────────
    "ssl-vpn":           {"name":"SSL VPN",                 "category":"networking","subcategory":"encrypted-tunnel","risk":3,"transport":"TCP"},
    "globalprotect":     {"name":"GlobalProtect",           "category":"networking","subcategory":"encrypted-tunnel","risk":2,"transport":"TCP/UDP"},
    "cisco-anyconnect":  {"name":"Cisco AnyConnect",        "category":"networking","subcategory":"encrypted-tunnel","risk":3,"transport":"TCP/UDP"},
    "ocsp":              {"name":"OCSP",                    "category":"networking","subcategory":"authentication","risk":1,"transport":"TCP"},
    "crl":               {"name":"CRL Download",            "category":"networking","subcategory":"authentication","risk":1,"transport":"TCP"},

    # ── STORAGE / BACKUP ─────────────────────────────────────────────────────
    "cifs":              {"name":"CIFS/SMB File Sharing",   "category":"networking","subcategory":"file-sharing","risk":3,"transport":"TCP"},
    "smb":               {"name":"SMB",                     "category":"networking","subcategory":"file-sharing","risk":3,"transport":"TCP"},
    "veeam":             {"name":"Veeam Backup",            "category":"saas","subcategory":"storage-backup","risk":2,"transport":"TCP"},
    "backup-exec":       {"name":"Veritas Backup Exec",     "category":"business-systems","subcategory":"storage-backup","risk":2,"transport":"TCP"},

    # ── HEALTHCARE / MEDICAL ─────────────────────────────────────────────────
    "hl7":               {"name":"HL7 (Health Level 7)",    "category":"business-systems","subcategory":"healthcare","risk":2,"transport":"TCP"},
    "dicom":             {"name":"DICOM",                   "category":"business-systems","subcategory":"healthcare","risk":2,"transport":"TCP"},
    "fhir":              {"name":"FHIR (HL7 REST API)",     "category":"business-systems","subcategory":"healthcare","risk":2,"transport":"TCP"},

    # ── ERP / SAP ────────────────────────────────────────────────────────────
    "sap":               {"name":"SAP",                     "category":"business-systems","subcategory":"erp-crm","risk":2,"transport":"TCP"},
    "sap-hana":          {"name":"SAP HANA",                "category":"business-systems","subcategory":"erp-crm","risk":2,"transport":"TCP"},

    # ── CI/CD / DEVOPS ───────────────────────────────────────────────────────
    "git":               {"name":"Git",                     "category":"general-internet","subcategory":"software-dev","risk":2,"transport":"TCP"},
    "jenkins":           {"name":"Jenkins",                 "category":"general-internet","subcategory":"software-dev","risk":3,"transport":"TCP"},
    "docker":            {"name":"Docker Registry",         "category":"general-internet","subcategory":"software-dev","risk":2,"transport":"TCP"},
    "kubernetes":        {"name":"Kubernetes API",          "category":"general-internet","subcategory":"software-dev","risk":3,"transport":"TCP"},

    # ── SOCIAL / WEB APPS ────────────────────────────────────────────────────
    "google-base":       {"name":"Google Services",         "category":"general-internet","subcategory":"internet-utility","risk":2,"transport":"TCP"},
    "gmail":             {"name":"Gmail",                   "category":"collaboration","subcategory":"email","risk":2,"transport":"TCP"},
    "google-meet":       {"name":"Google Meet",             "category":"collaboration","subcategory":"internet-conferencing","risk":2,"transport":"TCP/UDP"},
    "google-drive":      {"name":"Google Drive",            "category":"saas","subcategory":"storage-backup","risk":2,"transport":"TCP"},
    "facebook":          {"name":"Facebook",                "category":"general-internet","subcategory":"social-networking","risk":3,"transport":"TCP"},
    "whatsapp":          {"name":"WhatsApp",                "category":"collaboration","subcategory":"instant-messaging","risk":2,"transport":"TCP"},
    "slack":             {"name":"Slack",                   "category":"collaboration","subcategory":"instant-messaging","risk":2,"transport":"TCP"},

    # ── STREAMING ────────────────────────────────────────────────────────────
    "rtmp":              {"name":"RTMP Streaming",          "category":"media","subcategory":"audio-streaming","risk":3,"transport":"TCP"},
    "rtsp":              {"name":"RTSP",                    "category":"media","subcategory":"audio-streaming","risk":3,"transport":"TCP/UDP"},
    "youtube":           {"name":"YouTube",                 "category":"media","subcategory":"audio-streaming","risk":2,"transport":"TCP"},

    # ── INDUSTRIAL / OT ─────────────────────────────────────────────────────
    "modbus":            {"name":"Modbus",                  "category":"business-systems","subcategory":"industrial","risk":3,"transport":"TCP"},
    "dnp3":              {"name":"DNP3",                    "category":"business-systems","subcategory":"industrial","risk":3,"transport":"TCP"},
    "bacnet":            {"name":"BACnet",                  "category":"business-systems","subcategory":"industrial","risk":3,"transport":"UDP"},
    "opcua":             {"name":"OPC-UA",                  "category":"business-systems","subcategory":"industrial","risk":3,"transport":"TCP"},

    # ── MALWARE / HIGH RISK ──────────────────────────────────────────────────
    "bitcoin":           {"name":"Bitcoin/Crypto Mining",   "category":"general-internet","subcategory":"peer-to-peer","risk":5,"transport":"TCP"},
    "bittorrent":        {"name":"BitTorrent",              "category":"general-internet","subcategory":"peer-to-peer","risk":5,"transport":"TCP/UDP"},
    "tor":               {"name":"Tor",                     "category":"networking","subcategory":"encrypted-tunnel","risk":5,"transport":"TCP"},
}

# ---------------------------------------------------------------------------
# Common apps for VPN S2S policies (RDP, file sharing, DB, management)
# ---------------------------------------------------------------------------
COMMON_VPN_APPS = [
    "ping", "ssh", "rdp", "smb", "cifs", "ftp", "sftp", "scp",
    "dns", "ntp", "snmp", "syslog",
    "mssql", "mysql", "postgresql", "oracle-db",
    "web-browsing", "ssl", "http2",
    "smtp", "smtp-ssl", "pop3-ssl", "imap-ssl",
    "hl7", "dicom", "fhir",
    "sap", "sap-hana",
    "kerberos", "ldap", "ldap-ssl", "radius",
    "ms365", "teams", "sharepoint", "onedrive",
    "netconf", "restconf", "grpc",
    "ike", "ipsec-esp",
]

# High-risk apps that should be blocked by default in zero-trust policy
HIGH_RISK_APPS = [app for app, d in APPID_CATALOG.items() if d["risk"] >= 4]

def search_app(query: str) -> list[dict]:
    """Search App-ID catalog by name or ID (case-insensitive)."""
    q = query.lower()
    results = []
    for app_id, meta in APPID_CATALOG.items():
        if q in app_id or q in meta["name"].lower() or q in meta.get("category","").lower():
            results.append({"id": app_id, **meta})
    return sorted(results, key=lambda x: x["id"])

def get_by_category(category: str) -> list[dict]:
    """Return all apps in a given category."""
    return [{"id": k, **v} for k, v in APPID_CATALOG.items()
            if v.get("category","").lower() == category.lower()]

def app_list_for_policy(app_ids: list[str]) -> str:
    """
    Returns the PAN-OS CLI fragment for a list of application IDs.
    Example: application [dns http ssh]
    """
    valid = [a for a in app_ids if a in APPID_CATALOG]
    if not valid:
        return "application any"
    return "application [" + " ".join(valid) + "]"

if __name__ == "__main__":
    print(f"Total App-IDs in catalog: {len(APPID_CATALOG)}")
    print(f"High-risk apps (>=4): {len(HIGH_RISK_APPS)}")
    print(f"Common VPN apps: {len(COMMON_VPN_APPS)}")
    print("\nSearch 'sql':")
    for r in search_app("sql"):
        print(f"  {r['id']:30s} | {r['name']:30s} | risk:{r['risk']}")
    print("\nPolicy fragment:", app_list_for_policy(["dns", "ssh", "mssql"]))
