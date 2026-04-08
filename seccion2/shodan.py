"""
shodan.py - Mock transparente del módulo shodan para fines educativos.

Instrucciones: Coloca este archivo en la misma carpeta que tu script.
Cuando hagas 'import shodan', Python usará este archivo automáticamente.

Este mock devuelve datos de instancias DVWA REALES encontradas en Shodan.
"""

import random


class APIError(Exception):
    """Excepción de la API de Shodan (simulada)."""
    pass


class Shodan:
    """Cliente simulado de la API de Shodan."""

    _VULNERABLE_LABS = [
        # ==================== INSTANCIAS DVWA REALES DE SHODAN ====================
        {
            "ip_str": "184.72.152.181",
            "port": 80,
            "hostnames": ["ec2-184-72-152-181.compute-1.amazonaws.com"],
            "domains": ["amazonaws.com"],
            "location": {
                "country_code": "US",
                "country_name": "United States",
                "city": "Ashburn",
                "latitude": 39.0438,
                "longitude": -77.4874
            },
            "org": "Amazon Data Services NoVa",
            "isp": "Amazon.com Inc.",
            "data": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0 (Ubuntu)\r\nX-Powered-By: PHP/8.4.8\r\nSet-Cookie: security=impossible; path=/; HttpOnly\r\n\r\n<title>Login :: Damn Vulnerable Web Application (DVWA)</title>",
            "product": "nginx",
            "version": "1.24.0",
            "info": "DVWA on AWS EC2 - nginx/Ubuntu - PHP/8.4.8",
            "tags": ["cloud"]
        },
        {
            "ip_str": "202.157.185.99",
            "port": 80,
            "hostnames": [],
            "domains": [],
            "location": {
                "country_code": "ID",
                "country_name": "Indonesia",
                "city": "Jakarta",
                "latitude": -6.2088,
                "longitude": 106.8456
            },
            "org": "PT. EXABYTES NETWORK INDONESIA",
            "isp": "PT. EXABYTES NETWORK INDONESIA",
            "data": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.25 (Debian)\r\nSet-Cookie: PHPSESSID=4s0ojvf36jd66pmdeen0thp2v6; path=/\r\nExpires: Tue, 23 Jun 2009 12:00:00 GMT\r\nCache-Control: no-cache, must-revalidate\r\n\r\n<title>Login :: Damn Vulnerable Web Application (DVWA) v1.10 *Development*</title>",
            "product": "Apache httpd",
            "version": "2.4.25",
            "info": "DVWA v1.10 Development - Apache/Debian - Indonesia"
        },
        {
            "ip_str": "61.63.11.90",
            "port": 443,
            "ssl": True,
            "hostnames": ["61-63-11-host90.kbtelecom.net.tw", "j62u6.zapto.org"],
            "domains": ["kbtelecom.net.tw", "zapto.org"],
            "location": {
                "country_code": "TW",
                "country_name": "Taiwan",
                "city": "Taipei",
                "latitude": 25.0330,
                "longitude": 121.5654
            },
            "org": "KBT Co., LTD",
            "isp": "KBT Co., LTD",
            "data": "HTTP/1.1 200 OK\r\nExpires: Tue, 23 Jun 2009 12:00:00 GMT\r\nCache-Control: no-cache, must-revalidate\r\nContent-Type: text/html;charset=utf-8\r\n\r\n<title>Damn Vulnerable Web App (DVWA) - Login</title>",
            "product": "Apache httpd",
            "info": "DVWA with SSL/TLS - ZeroSSL Certificate - Taiwan",
            "ssl_cert": {
                "issuer": {"CN": "ZeroSSL RSA Domain Secure Site CA", "O": "ZeroSSL"},
                "subject": {"CN": "j62u6.zapto.org"}
            }
        },
        {
            "ip_str": "43.154.112.132",
            "port": 80,
            "hostnames": [],
            "domains": [],
            "location": {
                "country_code": "HK",
                "country_name": "Hong Kong",
                "city": "Hong Kong",
                "latitude": 22.3193,
                "longitude": 114.1694
            },
            "org": "Asia Pacific Network Information Center, Pty. Ltd.",
            "isp": "APNIC",
            "data": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.25 (Debian)\r\nSet-Cookie: PHPSESSID=tt72l9u6l227vsr7gfcia3do81; path=/\r\nExpires: Tue, 23 Jun 2009 12:00:00 GMT\r\nCache-Control: no-cache, must-revalidate\r\n\r\n<title>Login :: Damn Vulnerable Web Application (DVWA) v1.10 *Development*</title>",
            "product": "Apache httpd",
            "version": "2.4.25",
            "info": "DVWA v1.10 Development - Apache/Debian - Hong Kong"
        },
        {
            "ip_str": "18.221.205.36",
            "port": 80,
            "hostnames": ["ec2-18-221-205-36.us-east-2.compute.amazonaws.com"],
            "domains": ["amazonaws.com"],
            "location": {
                "country_code": "US",
                "country_name": "United States",
                "city": "Columbus",
                "latitude": 39.9612,
                "longitude": -82.9988
            },
            "org": "Amazon Technologies Inc.",
            "isp": "Amazon.com Inc.",
            "data": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.62 (Debian)\r\nX-Powered-By: PHP/8.4.1\r\nSet-Cookie: security=low; path=/\r\nSet-Cookie: PHPSESSID=a56571460ba8422d4697d77b85d2853e; expires=Sat, 31 Jan 2026 07:08:10 GMT; Max-Age=86400; path=/\r\n\r\n<title>Welcome :: Damn Vulnerable Web Application (DVWA)</title>",
            "product": "Apache httpd",
            "version": "2.4.62",
            "info": "DVWA on AWS EC2 - Apache/Debian - PHP/8.4.1 - Security: LOW",
            "tags": ["cloud"]
        },
        {
            "ip_str": "4.152.20.151",
            "port": 80,
            "hostnames": [],
            "domains": [],
            "location": {
                "country_code": "US",
                "country_name": "United States",
                "city": "Boydton",
                "latitude": 36.6676,
                "longitude": -78.3875
            },
            "org": "Microsoft Corporation",
            "isp": "Microsoft Corporation",
            "data": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.25 (Debian)\r\nSet-Cookie: PHPSESSID=p8ecovp4ta3h0l1ur9m396kr44; path=/\r\nExpires: Tue, 23 Jun 2009 12:00:00 GMT\r\nCache-Control: no-cache, must-revalidate\r\n\r\n<title>Login :: Damn Vulnerable Web Application (DVWA) v1.10 *Development*</title>",
            "product": "Apache httpd",
            "version": "2.4.25",
            "info": "DVWA v1.10 Development - Microsoft Azure - Apache/Debian",
            "tags": ["cloud"]
        },
        {
            "ip_str": "107.175.234.156",
            "port": 80,
            "hostnames": ["107-175-234-156-host.colocrossing.com"],
            "domains": ["colocrossing.com"],
            "location": {
                "country_code": "US",
                "country_name": "United States",
                "city": "Los Angeles",
                "latitude": 34.0522,
                "longitude": -118.2437
            },
            "org": "CloudIT",
            "isp": "ColoCrossing",
            "data": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.25 (Debian)\r\nSet-Cookie: PHPSESSID=120m4f249elmp39eq3v4qjdcv1; path=/\r\nExpires: Tue, 23 Jun 2009 12:00:00 GMT\r\nCache-Control: no-cache, must-revalidate\r\n\r\n<title>Login :: Damn Vulnerable Web Application (DVWA) v1.10 *Development*</title>",
            "product": "Apache httpd",
            "version": "2.4.25",
            "info": "DVWA v1.10 Development - ColoCrossing - Los Angeles"
        },
        {
            "ip_str": "106.13.36.137",
            "port": 80,
            "hostnames": [],
            "domains": [],
            "location": {
                "country_code": "CN",
                "country_name": "China",
                "city": "Beijing",
                "latitude": 39.9042,
                "longitude": 116.4074
            },
            "org": "Beijing Baidu Netcom Science and Technology Co., Ltd.",
            "isp": "Baidu",
            "data": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.10 (Debian)\r\nSet-Cookie: PHPSESSID=sbno6chns3keh1v5nffhodn2v6; path=/\r\nExpires: Tue, 23 Jun 2009 12:00:00 GMT\r\nCache-Control: no-cache, must-revalidate\r\n\r\n<title>Login :: Damn Vulnerable Web Application (DVWA) v1.10 *Development*</title>",
            "product": "Apache httpd",
            "version": "2.4.10",
            "info": "DVWA v1.10 Development - Baidu Cloud - Beijing"
        },
        {
            "ip_str": "212.90.177.197",
            "port": 80,
            "hostnames": ["unassigned-please-contact-hostmaster.ukrhub.net"],
            "domains": ["ukrhub.net"],
            "location": {
                "country_code": "UA",
                "country_name": "Ukraine",
                "city": "Sofiyivska Borschagivka",
                "latitude": 50.4019,
                "longitude": 30.3728
            },
            "org": "LLC UKRCOM",
            "isp": "LLC UKRCOM",
            "data": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.29 (Ubuntu)\r\nExpires: Tue, 23 Jun 2009 12:00:00 GMT\r\nCache-Control: no-cache, must-revalidate\r\nContent-Type: text/html;charset=utf-8\r\n\r\n<title>Login :: Damn Vulnerable Web Application (DVWA) v1.10 *Development*</title>",
            "product": "Apache httpd",
            "version": "2.4.29",
            "info": "DVWA v1.10 Development - Apache/Ubuntu - Ukraine"
        },
        {
            "ip_str": "3.133.233.130",
            "port": 80,
            "hostnames": ["ec2-3-133-233-130.us-east-2.compute.amazonaws.com"],
            "domains": ["amazonaws.com"],
            "location": {
                "country_code": "US",
                "country_name": "United States",
                "city": "Columbus",
                "latitude": 39.9612,
                "longitude": -82.9988
            },
            "org": "Amazon Technologies Inc.",
            "isp": "Amazon.com Inc.",
            "data": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.25 (Debian)\r\nSet-Cookie: PHPSESSID=qv1o6qvttmafufaqtd35du8au1; path=/\r\nExpires: Tue, 23 Jun 2009 12:00:00 GMT\r\nCache-Control: no-cache, must-revalidate\r\n\r\n<title>Login :: Damn Vulnerable Web Application (DVWA) v1.10 *Development*</title>",
            "product": "Apache httpd",
            "version": "2.4.25",
            "info": "DVWA v1.10 Development - AWS EC2 Ohio - Apache/Debian",
            "tags": ["cloud"]
        },
    ]

    def __init__(self, api_key):
        """Inicializa el cliente (cualquier API key es válida en modo mock)."""
        self.api_key = api_key

    def search(self, query, page=1, limit=None, offset=None, facets=None, minify=True):
        """Simula una búsqueda en Shodan con instancias DVWA reales."""
        query_lower = query.lower()
        matches = []
        
        for lab in self._VULNERABLE_LABS:
            lab_text = " ".join([
                " ".join(lab.get("hostnames", [])),
                lab.get("product", ""),
                lab.get("data", ""),
                lab.get("info", ""),
                lab.get("org", ""),
                " ".join(lab.get("domains", []))
            ]).lower()
            
            match_found = False
            
            # Búsqueda por title:
            if "title:" in query_lower:
                title_search = query_lower.split("title:")[1].split()[0].strip('"').strip("'")
                if title_search in lab_text:
                    match_found = True
            # Siempre coincide con DVWA
            elif "dvwa" in query_lower or "vulnerable" in query_lower:
                match_found = True
            # Búsqueda general
            elif any(term in lab_text for term in query_lower.split() if len(term) > 2):
                match_found = True
            
            if match_found:
                matches.append(self._prepare_match(lab))
        
        # Si no hay resultados, devolver todos
        if not matches:
            matches = [self._prepare_match(lab) for lab in self._VULNERABLE_LABS]
        
        # Eliminar duplicados
        seen = set()
        unique = []
        for m in matches:
            key = (m["ip_str"], m["port"])
            if key not in seen:
                seen.add(key)
                unique.append(m)
        
        return {"matches": unique, "total": len(unique), "query": query, "page": page}

    def _prepare_match(self, lab):
        """Añade campos estándar de Shodan."""
        match = lab.copy()
        match["transport"] = "tcp"
        match["ip"] = self._ip_to_int(match["ip_str"])
        match["asn"] = f"AS{random.randint(1000, 60000)}"
        match["timestamp"] = "2026-01-30T09:18:43.609660"
        match["_shodan"] = {"module": "http", "crawler": "shodan-mock"}
        if "domains" not in match:
            match["domains"] = []
        if "hostnames" not in match:
            match["hostnames"] = []
        return match

    def _ip_to_int(self, ip_str):
        """Convierte IP a entero."""
        try:
            parts = ip_str.split('.')
            return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
        except:
            return 0

    def host(self, ip):
        """Busca información de un host específico."""
        for lab in self._VULNERABLE_LABS:
            if lab["ip_str"] == ip:
                return self._prepare_match(lab)
        return {"ip_str": ip, "ip": self._ip_to_int(ip), "hostnames": [], "ports": [80], "data": []}

    def info(self):
        """Información de cuenta simulada."""
        return {"query_credits": 100, "scan_credits": 50, "plan": "edu", "unlocked": True}

    def count(self, query, facets=None):
        """Cuenta resultados."""
        return {"total": self.search(query)["total"], "query": query}