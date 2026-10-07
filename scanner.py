import socket

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 8080]

def scan_ports(target):
    results = []

    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        return [{"port": "-", "status": "INVALID", "service": "Unknown"}]

    services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 139: "NetBIOS",
        143: "IMAP", 443: "HTTPS", 445: "SMB",
        3306: "MySQL", 8080: "HTTP-Alt"
    }

    for port in COMMON_PORTS:
        sock = socket.socket()
        sock.settimeout(0.25)

        try:
            status = "OPEN" if sock.connect_ex((ip, port)) == 0 else "CLOSED"
        except Exception:
            status = "CLOSED"
        finally:
            sock.close()

        results.append({
            "port": port,
            "status": status,
            "service": services.get(port, "Unknown")
        })

    return results
