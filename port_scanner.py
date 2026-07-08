#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PortScanner - nmap 유사 포트 스캐너 (FortiGate 점검 도구 ⑦ 포트 분석 탭 연동용)
================================================================================
IP 를 입력하면 대상 호스트의 포트 개폐 여부를 확인하고, 열린 포트에 대해
서비스/배너/OS 정보를 수집한다. 결과는 nmap 형식으로도 출력되므로
단일 HTML 점검 도구의 "⑦ 포트/서비스 위험도 분석" 탭에 그대로 붙여넣을 수 있다.

- 순수 표준 라이브러리만 사용 (관리자 권한 불필요, 단일 exe 로 패키징 가능)
- TCP connect 스캔 (멀티스레드)
- 배너 그래빙 기반 서비스 식별
- TTL + 배너 기반 OS 추정
- 역방향 DNS / 응답시간 측정
"""

import argparse
import concurrent.futures
import ipaddress
import json
import platform
import re
import socket
import subprocess
import sys
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

APP_NAME = "PortScanner"
APP_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# 잘 알려진 포트 -> 서비스 이름 (nmap 형식 출력용)
# ---------------------------------------------------------------------------
WELL_KNOWN = {
    7: "echo", 19: "chargen", 20: "ftp-data", 21: "ftp", 22: "ssh",
    23: "telnet", 25: "smtp", 37: "time", 43: "whois", 49: "tacacs",
    53: "domain", 67: "dhcps", 68: "dhcpc", 69: "tftp", 79: "finger",
    80: "http", 88: "kerberos-sec", 110: "pop3", 111: "rpcbind",
    113: "ident", 119: "nntp", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    162: "snmptrap", 179: "bgp", 194: "irc", 389: "ldap", 443: "https",
    445: "microsoft-ds", 465: "smtps", 500: "isakmp", 512: "exec",
    513: "login", 514: "shell", 515: "printer", 520: "route", 521: "ripng",
    540: "uucp", 543: "klogin", 544: "kshell", 548: "afp", 554: "rtsp",
    587: "submission", 631: "ipp", 636: "ldaps", 646: "ldp", 873: "rsync",
    902: "vmware", 989: "ftps-data", 990: "ftps", 993: "imaps",
    995: "pop3s", 1080: "socks", 1194: "openvpn", 1433: "ms-sql-s",
    1434: "ms-sql-m", 1521: "oracle", 1723: "pptp", 1812: "radius",
    1813: "radius-acct", 1900: "upnp", 2000: "cisco-sccp", 2049: "nfs",
    2082: "cpanel", 2083: "cpanel-ssl", 2181: "zookeeper", 2222: "ssh-alt",
    2375: "docker", 2376: "docker-ssl", 3000: "http-alt", 3128: "squid",
    3268: "globalcat", 3306: "mysql", 3389: "ms-wbt-server", 3690: "svn",
    4443: "https-alt", 4444: "metasploit", 4500: "ipsec-nat-t",
    5000: "upnp", 5060: "sip", 5061: "sip-tls", 5432: "postgresql",
    5555: "freeciv", 5601: "kibana", 5900: "vnc", 5985: "winrm",
    5986: "winrm-ssl", 6379: "redis", 6443: "kubernetes", 6660: "irc",
    6667: "irc", 7001: "weblogic", 8000: "http-alt", 8008: "http-alt",
    8080: "http-proxy", 8081: "http-alt", 8083: "http-alt", 8088: "http-alt",
    8443: "https-alt", 8888: "http-alt", 9000: "http-alt", 9090: "http-alt",
    9200: "elasticsearch", 9300: "elasticsearch", 9443: "https-alt",
    10000: "webmin", 10443: "https-alt", 11211: "memcached",
    27017: "mongodb", 27018: "mongodb", 50000: "sap",
}

# 빠른 스캔 시 사용하는 상위 공통 포트
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 137, 139, 143, 161, 179, 389,
    443, 445, 465, 500, 514, 515, 587, 631, 636, 873, 990, 993, 995, 1080,
    1194, 1433, 1521, 1723, 1812, 2049, 2082, 2083, 2181, 2222, 2375, 3000,
    3128, 3268, 3306, 3389, 4443, 4500, 5000, 5060, 5432, 5601, 5900, 5985,
    5986, 6379, 6443, 6667, 7001, 8000, 8008, 8080, 8081, 8443, 8888, 9000,
    9090, 9200, 9300, 9443, 10000, 10443, 11211, 27017, 50000,
]

# 서비스 식별에 사용할 프로브 (배너를 유도하기 위한 요청)
HTTP_PORTS = {80, 443, 591, 2082, 2083, 3000, 5000, 5601, 7001, 8000, 8008,
              8080, 8081, 8083, 8088, 8443, 8888, 9000, 9090, 9200, 9443,
              10000, 10443}
TLS_PORTS = {443, 465, 636, 989, 990, 993, 995, 3269, 4443, 5061, 5986,
             6443, 8443, 9443, 10443}


# ---------------------------------------------------------------------------
# 콘솔 컬러 (Windows 10+ 및 대부분 터미널 지원)
# ---------------------------------------------------------------------------
class C:
    R = "\033[91m"   # red
    G = "\033[92m"   # green
    Y = "\033[93m"   # yellow
    B = "\033[94m"   # blue
    M = "\033[95m"   # magenta
    CY = "\033[96m"  # cyan
    W = "\033[97m"   # white
    BOLD = "\033[1m"
    DIM = "\033[2m"
    END = "\033[0m"

    @classmethod
    def disable(cls):
        for k in ("R", "G", "Y", "B", "M", "CY", "W", "BOLD", "DIM", "END"):
            setattr(cls, k, "")


def enable_windows_ansi():
    """Windows 콘솔에서 ANSI 컬러를 활성화한다."""
    if platform.system() == "Windows":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            C.disable()


# ---------------------------------------------------------------------------
# 대상 해석
# ---------------------------------------------------------------------------
def resolve_target(target):
    """호스트명/IP 를 (ip, 표시이름, 역방향DNS) 로 해석한다."""
    ip = None
    forward_name = None
    try:
        ipaddress.ip_address(target)
        ip = target
    except ValueError:
        # 호스트명 -> IP
        try:
            ip = socket.gethostbyname(target)
            forward_name = target
        except socket.gaierror:
            return None, None, None
    # 역방향 DNS
    rdns = None
    try:
        rdns = socket.gethostbyaddr(ip)[0]
    except Exception:
        rdns = None
    return ip, forward_name, rdns


# ---------------------------------------------------------------------------
# TTL / 응답시간 측정 (시스템 ping 이용 - 관리자 권한 불필요)
# ---------------------------------------------------------------------------
def ping_host(ip, timeout=2):
    """시스템 ping 을 실행해 (도달여부, TTL, 평균응답ms) 를 반환한다."""
    system = platform.system()
    if system == "Windows":
        cmd = ["ping", "-n", "2", "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "2", "-W", str(int(timeout)), ip]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout * 4 + 4)
        text = (out.stdout or "") + (out.stderr or "")
    except Exception:
        return False, None, None

    ttl = None
    m = re.search(r"[Tt][Tt][Ll]\s*[=:]\s*(\d+)", text)
    if m:
        ttl = int(m.group(1))

    avg = None
    # Windows: Average = 12ms / Linux: rtt min/avg/max/mdev = .../12.3/...
    m2 = re.search(r"[Aa]verage\s*=\s*(\d+)ms", text)
    if m2:
        avg = float(m2.group(1))
    else:
        m3 = re.search(r"=\s*[\d.]+/([\d.]+)/", text)
        if m3:
            avg = float(m3.group(1))

    reachable = ttl is not None or "bytes from" in text.lower() or \
        "reply from" in text.lower()
    return reachable, ttl, avg


def guess_os_from_ttl(ttl):
    """TTL 초기값 추정으로 OS 계열을 추정한다."""
    if ttl is None:
        return None
    # 관측 TTL 이하의 가장 가까운 초기 TTL(64/128/255) 을 찾는다
    for initial, label in ((64, "Linux/Unix 계열"),
                           (128, "Windows 계열"),
                           (255, "네트워크 장비(라우터/스위치/방화벽) 또는 Unix")):
        if ttl <= initial:
            hops = initial - ttl
            if hops <= 30:
                return f"{label} (초기 TTL {initial}, 홉 약 {hops})"
    return None


# ---------------------------------------------------------------------------
# 포트 스캔 (TCP connect)
# ---------------------------------------------------------------------------
def scan_port(ip, port, timeout):
    """단일 포트 TCP connect 스캔. 열려있으면 port, 아니면 None."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip, port))
        if result == 0:
            return port
    except Exception:
        pass
    finally:
        sock.close()
    return None


def grab_banner(ip, port, timeout=2.5):
    """열린 포트에서 배너를 수집한다."""
    banner = ""
    try:
        if port in TLS_PORTS:
            return _grab_tls_banner(ip, port, timeout)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        if port in HTTP_PORTS or port >= 8000:
            req = ("GET / HTTP/1.0\r\nHost: %s\r\n"
                   "User-Agent: PortScanner\r\n\r\n" % ip)
            sock.sendall(req.encode())
        # 그 외 서비스는 서버가 먼저 배너를 보내는 경우가 많음(SSH/FTP/SMTP 등)

        data = sock.recv(2048)
        banner = data.decode("utf-8", errors="replace").strip()
        sock.close()
    except Exception:
        pass
    return _clean_banner(banner)


def _grab_tls_banner(ip, port, timeout):
    """TLS 포트에서 인증서 정보를 통해 힌트를 얻는다."""
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((ip, port), timeout=timeout)
        ssock = ctx.wrap_socket(raw, server_hostname=ip)
        info_bits = []
        try:
            cert = ssock.getpeercert()
            if cert:
                subj = dict(x[0] for x in cert.get("subject", []))
                cn = subj.get("commonName")
                if cn:
                    info_bits.append("CN=%s" % cn)
        except Exception:
            pass
        # HTTPS 라면 HTTP 응답도 시도
        if port in HTTP_PORTS or port in (443, 4443, 8443, 9443, 10443):
            try:
                ssock.sendall(("GET / HTTP/1.0\r\nHost: %s\r\n\r\n" % ip).encode())
                data = ssock.recv(1024).decode("utf-8", errors="replace")
                server = re.search(r"[Ss]erver:\s*([^\r\n]+)", data)
                if server:
                    info_bits.append(server.group(1).strip())
            except Exception:
                pass
        ssock.close()
        return _clean_banner(" | ".join(info_bits))
    except Exception:
        return ""


def _clean_banner(banner):
    if not banner:
        return ""
    banner = banner.replace("\r", " ").replace("\n", " ")
    banner = re.sub(r"\s+", " ", banner).strip()
    return banner[:200]


def identify_service(port, banner):
    """포트 번호 + 배너로 서비스명을 추정한다 (nmap 형식용)."""
    name = WELL_KNOWN.get(port)
    if banner:
        low = banner.lower()
        if "ssh" in low:
            name = "ssh"
        elif "ftp" in low and port != 22:
            name = "ftp"
        elif "smtp" in low or "esmtp" in low:
            name = "smtp"
        elif "http" in low or "server:" in low:
            name = name or "http"
        elif "mysql" in low:
            name = "mysql"
        elif "postgres" in low:
            name = "postgresql"
        elif "redis" in low:
            name = "redis"
    return name or "unknown"


def fingerprint_product(banner):
    """배너에서 제품/버전 정보를 뽑아낸다."""
    if not banner:
        return ""
    patterns = [
        r"(OpenSSH[_/\s][\w.\-p]+)",
        r"(Microsoft-IIS/[\d.]+)",
        r"(Apache/[\d.]+)",
        r"(nginx/[\d.]+)",
        r"(nginx)",
        r"(vsftpd [\d.]+)",
        r"(ProFTPD [\d.]+)",
        r"(Postfix)",
        r"(Exim [\d.]+)",
        r"(MySQL[\w.\-]*)",
        r"(FortiGate|FortiOS|Fortinet)",
        r"(Cisco[\w\s.\-]*)",
        r"(Ubuntu)",
        r"(Debian)",
        r"(CentOS)",
        r"(Red Hat)",
        r"(Windows)",
    ]
    hits = []
    for p in patterns:
        m = re.search(p, banner, re.IGNORECASE)
        if m and m.group(1) not in hits:
            hits.append(m.group(1))
    return ", ".join(hits)


def refine_os_from_banners(os_guess, open_ports):
    """수집한 배너로 OS 추정을 보강한다."""
    hints = []
    for info in open_ports:
        b = (info.get("banner") or "").lower()
        prod = (info.get("product") or "").lower()
        blob = b + " " + prod
        if "windows" in blob or "microsoft-iis" in blob or "microsoft-ds" == info.get("service"):
            hints.append("Windows")
        if "ubuntu" in blob:
            hints.append("Linux (Ubuntu)")
        if "debian" in blob:
            hints.append("Linux (Debian)")
        if "centos" in blob or "red hat" in blob:
            hints.append("Linux (RHEL/CentOS)")
        if "fortigate" in blob or "fortios" in blob or "fortinet" in blob:
            hints.append("Fortinet FortiOS")
        if "cisco" in blob:
            hints.append("Cisco IOS/장비")
        if "openssh" in blob and "windows" not in blob:
            hints.append("Linux/Unix (OpenSSH)")
    # netbios/smb 포트로 Windows 강력 추정
    ports = {p["port"] for p in open_ports}
    if {135, 139, 445} & ports or 3389 in ports or 5985 in ports:
        hints.append("Windows (SMB/RDP/WinRM 포트 감지)")

    uniq = []
    for h in hints:
        if h not in uniq:
            uniq.append(h)
    parts = []
    if os_guess:
        parts.append(os_guess)
    if uniq:
        parts.append("배너 근거: " + "; ".join(uniq))
    return " | ".join(parts) if parts else "판별 불가"


# ---------------------------------------------------------------------------
# 스캔 오케스트레이션
# ---------------------------------------------------------------------------
def run_scan(ip, ports, timeout, workers, on_progress=None):
    """포트 목록을 병렬 스캔하고 열린 포트 리스트를 반환한다."""
    open_ports = []
    done = 0
    total = len(ports)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(scan_port, ip, p, timeout): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            done += 1
            if on_progress:
                on_progress(done, total)
            p = fut.result()
            if p is not None:
                open_ports.append(p)
    return sorted(open_ports)


def parse_ports(spec):
    """'1-1024,3389,8080' 형태 또는 'top'/'all' 을 포트 리스트로 변환한다."""
    spec = (spec or "").strip().lower()
    if spec in ("", "top", "common"):
        return sorted(set(TOP_PORTS))
    if spec == "all":
        return list(range(1, 65536))
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            try:
                a, b = int(a), int(b)
                for p in range(min(a, b), max(a, b) + 1):
                    if 1 <= p <= 65535:
                        ports.add(p)
            except ValueError:
                continue
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                continue
    return sorted(ports)


# ---------------------------------------------------------------------------
# 출력
# ---------------------------------------------------------------------------
def print_progress(done, total):
    width = 30
    filled = int(width * done / total) if total else width
    bar = "#" * filled + "-" * (width - filled)
    pct = int(100 * done / total) if total else 100
    sys.stdout.write("\r  스캔 중 [%s] %d/%d (%d%%)" % (bar, done, total, pct))
    sys.stdout.flush()
    if done >= total:
        sys.stdout.write("\n")


def build_nmap_block(ip, open_infos):
    """HTML 도구 ⑦ 탭에 붙여넣을 nmap 형식 텍스트를 만든다."""
    lines = []
    lines.append("# Nmap 유사 스캔 결과 - %s" % ip)
    lines.append("PORT      STATE  SERVICE         VERSION")
    for info in open_infos:
        port = info["port"]
        svc = info["service"]
        ver = info.get("product") or ""
        line = "%-9s open  %-15s %s" % ("%d/tcp" % port, svc, ver)
        lines.append(line.rstrip())
    return "\n".join(lines)


def build_report(ip, meta, open_infos, scanned_count, elapsed):
    lines = []
    lines.append("=" * 68)
    lines.append(" %s v%s - 스캔 리포트" % (APP_NAME, APP_VERSION))
    lines.append("=" * 68)
    lines.append(" 대상 IP        : %s" % ip)
    if meta.get("forward_name"):
        lines.append(" 입력 호스트명  : %s" % meta["forward_name"])
    lines.append(" 역방향 DNS     : %s" % (meta.get("rdns") or "-"))
    lines.append(" 도달 여부      : %s" % ("응답함" if meta.get("reachable") else "무응답(ICMP 차단 가능)"))
    if meta.get("ttl") is not None:
        lines.append(" 관측 TTL       : %s" % meta["ttl"])
    if meta.get("rtt") is not None:
        lines.append(" 평균 응답시간  : %.1f ms" % meta["rtt"])
    lines.append(" 추정 OS        : %s" % meta.get("os", "판별 불가"))
    lines.append(" 스캔 포트 수   : %d" % scanned_count)
    lines.append(" 열린 포트 수   : %d" % len(open_infos))
    lines.append(" 소요 시간      : %.1f 초" % elapsed)
    lines.append(" 스캔 시각      : %s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    lines.append("-" * 68)
    if open_infos:
        lines.append(" %-9s %-16s %s" % ("PORT", "SERVICE", "BANNER/VERSION"))
        lines.append("-" * 68)
        for info in open_infos:
            ver = info.get("product") or info.get("banner") or ""
            lines.append(" %-9s %-16s %s" % ("%d/tcp" % info["port"],
                                             info["service"], ver[:40]))
    else:
        lines.append(" 열린 TCP 포트가 없습니다.")
    lines.append("=" * 68)
    return "\n".join(lines)


def colorize_report(report):
    out = []
    for line in report.split("\n"):
        if line.startswith("=") or "스캔 리포트" in line:
            out.append(C.CY + C.BOLD + line + C.END)
        elif "/tcp" in line and "open" not in line:
            out.append(C.G + line + C.END)
        elif "추정 OS" in line:
            out.append(C.Y + line + C.END)
        else:
            out.append(line)
    return "\n".join(out)


# ---------------------------------------------------------------------------
# 메인 스캔 절차
# ---------------------------------------------------------------------------
def scan_target(target, port_spec, timeout, workers, quiet=False):
    ip, forward_name, rdns = resolve_target(target)
    if ip is None:
        print(C.R + "[!] 대상을 해석할 수 없습니다: %s" % target + C.END)
        return None

    if not quiet:
        print()
        print(C.B + C.BOLD + "[*] 대상 해석: %s -> %s" % (target, ip) + C.END)
        if rdns:
            print(C.DIM + "    역방향 DNS: %s" % rdns + C.END)

    # 호스트 상태 확인
    reachable, ttl, rtt = ping_host(ip, timeout=2)
    os_guess = guess_os_from_ttl(ttl)
    if not quiet:
        status = C.G + "응답함" + C.END if reachable else C.Y + "ICMP 무응답 (포트 스캔은 계속 진행)" + C.END
        print(C.B + "[*] 호스트 상태: %s%s" % (
            status,
            (" (TTL=%s)" % ttl) if ttl is not None else "") + C.END)

    ports = parse_ports(port_spec)
    if not quiet:
        print(C.B + "[*] 포트 %d개 스캔 시작 (타임아웃 %.1fs, 스레드 %d)" % (
            len(ports), timeout, workers) + C.END)

    start = time.time()
    open_ports = run_scan(ip, ports, timeout, workers,
                          on_progress=None if quiet else print_progress)

    # 열린 포트 상세 조사
    open_infos = []
    if open_ports and not quiet:
        print(C.B + "[*] 열린 포트 %d개 상세 조사 (배너/서비스)..." % len(open_ports) + C.END)
    for port in open_ports:
        banner = grab_banner(ip, port, timeout=max(timeout, 2.5))
        service = identify_service(port, banner)
        product = fingerprint_product(banner)
        open_infos.append({
            "port": port, "service": service,
            "banner": banner, "product": product,
        })

    elapsed = time.time() - start
    os_final = refine_os_from_banners(os_guess, open_infos)

    meta = {
        "ip": ip, "forward_name": forward_name, "rdns": rdns,
        "reachable": reachable, "ttl": ttl, "rtt": rtt, "os": os_final,
    }
    return {
        "meta": meta, "open": open_infos,
        "scanned": len(ports), "elapsed": elapsed,
    }


def save_results(result, path):
    ip = result["meta"]["ip"]
    report = build_report(ip, result["meta"], result["open"],
                          result["scanned"], result["elapsed"])
    nmap = build_nmap_block(ip, result["open"])
    with open(path, "w", encoding="utf-8") as f:
        f.write(report + "\n\n")
        f.write("[ HTML 도구 ⑦ 포트 분석 탭에 붙여넣기용 (nmap 형식) ]\n")
        f.write(nmap + "\n")
    return path


# ---------------------------------------------------------------------------
# HTML 연동 브리지 (로컬 HTTP 서버)
# ---------------------------------------------------------------------------
def result_to_dict(result):
    """scan_target 결과를 HTML 이 소비할 JSON 딕셔너리로 변환한다."""
    m = result["meta"]
    return {
        "ok": True,
        "app": APP_NAME,
        "version": APP_VERSION,
        "target": m.get("forward_name") or m["ip"],
        "ip": m["ip"],
        "rdns": m.get("rdns"),
        "reachable": m.get("reachable"),
        "ttl": m.get("ttl"),
        "rtt": m.get("rtt"),
        "os": m.get("os"),
        "scanned": result["scanned"],
        "elapsed": round(result["elapsed"], 2),
        "openCount": len(result["open"]),
        "open": result["open"],
        "nmap": build_nmap_block(m["ip"], result["open"]),
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


class _BridgeHandler(BaseHTTPRequestHandler):
    server_version = "%s/%s" % (APP_NAME, APP_VERSION)

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        # Chrome Private Network Access 대응 (공용/파일 페이지 -> 사설 IP)
        self.send_header("Access-Control-Allow-Private-Network", "true")

    def _json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self._cors()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        qs = parse_qs(parsed.query)

        def q(name, default=None):
            v = qs.get(name)
            return v[0] if v else default

        if path in ("", "/health"):
            self._json({"ok": True, "app": APP_NAME, "version": APP_VERSION,
                        "status": "running"})
            return

        if path == "/scan":
            target = q("target") or q("ip")
            if not target:
                self._json({"ok": False, "error": "target 파라미터가 필요합니다."},
                           status=400)
                return
            ports = q("ports", "top")
            try:
                timeout = float(q("timeout", "1.0"))
                workers = int(q("workers", "200"))
            except ValueError:
                timeout, workers = 1.0, 200
            print("  [브리지] 스캔 요청: %s (ports=%s)" % (target, ports))
            try:
                result = scan_target(target, ports, timeout, workers, quiet=True)
            except Exception as e:  # noqa
                self._json({"ok": False, "error": "스캔 오류: %s" % e}, status=500)
                return
            if not result:
                self._json({"ok": False,
                            "error": "대상을 해석할 수 없습니다: %s" % target},
                           status=400)
                return
            data = result_to_dict(result)
            print("  [브리지] 완료: %s 열린포트 %d개 (%.1fs)" % (
                data["ip"], data["openCount"], data["elapsed"]))
            self._json(data)
            return

        self._json({"ok": False, "error": "알 수 없는 경로: %s" % path}, status=404)

    def log_message(self, fmt, *args):
        # 기본 접근 로그는 억제 (요청 로그는 do_GET 에서 직접 출력)
        pass


def serve_bridge(host="127.0.0.1", port=8765):
    enable_windows_ansi()
    try:
        httpd = ThreadingHTTPServer((host, port), _BridgeHandler)
    except OSError as e:
        print(C.R + "[!] 브리지 서버를 시작할 수 없습니다 (%s:%d): %s" % (
            host, port, e) + C.END)
        print(C.Y + "    다른 포트로 실행: PortScanner --serve --serve-port 8766" + C.END)
        sys.exit(1)
    print(C.CY + C.BOLD + "\n  == %s HTML 연동 브리지 서버 ==" % APP_NAME + C.END)
    print(C.G + "  실행 중: http://%s:%d" % (host, port) + C.END)
    print(C.DIM + "  상태확인: http://%s:%d/health" % (host, port) + C.END)
    print(C.W + "  이제 HTML 점검 도구 ⑦ 탭에서 '실시간 스캔' 을 사용할 수 있습니다." + C.END)
    print(C.Y + "  ※ 본인 소유/허가된 대상만 스캔하세요. (종료: Ctrl+C)\n" + C.END)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n브리지 서버를 종료합니다.")
        httpd.shutdown()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def print_banner():
    enable_windows_ansi()
    print(C.CY + C.BOLD + r"""
   ____            _   ____
  |  _ \ ___  _ __| |_/ ___|  ___ __ _ _ __  _ __   ___ _ __
  | |_) / _ \| '__| __\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
  |  __/ (_) | |  | |_ ___) | (_| (_| | | | | | | |  __/ |
  |_|   \___/|_|   \__|____/ \___\__,_|_| |_|_| |_|\___|_|
""" + C.END)
    print(C.DIM + "  %s v%s  -  FortiGate 점검 도구 ⑦ 포트 분석 연동 스캐너" % (
        APP_NAME, APP_VERSION) + C.END)
    print(C.Y + "  ※ 본인이 관리하거나 명시적으로 스캔 허가를 받은 대상에만 사용하세요." + C.END)


def startup_chooser():
    """더블클릭(인자 없음) 실행 시 단일/서버 모드를 선택하는 시작 화면."""
    print_banner()
    while True:
        print()
        print(C.W + C.BOLD + "  실행 모드를 선택하세요:" + C.END)
        print("    1) 단일 스캔 모드   - IP 를 직접 입력해 콘솔에서 스캔")
        print("    2) 서버 모드        - HTML ⑦ 탭의 '실시간 스캔' 과 연동")
        print(C.DIM + "    q) 종료" + C.END)
        try:
            choice = input(C.W + "  선택 [1] > " + C.END).strip().lower() or "1"
        except (EOFError, KeyboardInterrupt):
            print("\n종료합니다.")
            return

        if choice in ("q", "quit", "exit"):
            print("종료합니다.")
            return
        if choice == "1":
            interactive_menu(show_banner=False)
            return
        if choice == "2":
            try:
                pin = input(C.W + "  서버 포트 [8765] > " + C.END).strip()
            except (EOFError, KeyboardInterrupt):
                print("\n종료합니다.")
                return
            try:
                port = int(pin) if pin else 8765
            except ValueError:
                port = 8765
            # 서버는 이 프로세스에서 실행되므로 창을 닫거나 Ctrl+C 시 함께 종료됨
            serve_bridge("127.0.0.1", port)
            return
        print(C.Y + "  1, 2 또는 q 를 입력하세요." + C.END)


def interactive_menu(show_banner=True):
    if show_banner:
        print_banner()
        print()

    while True:
        try:
            target = input(C.W + "  대상 IP 또는 호스트명 (종료: q) > " + C.END).strip()
        except (EOFError, KeyboardInterrupt):
            print("\n종료합니다.")
            return
        if target.lower() in ("q", "quit", "exit"):
            print("종료합니다.")
            return
        if not target:
            continue

        print(C.DIM + "  포트 범위 선택:" + C.END)
        print("    1) 주요 공통 포트 (빠름, 기본)")
        print("    2) 1-1024 (well-known)")
        print("    3) 1-65535 (전체, 느림)")
        print("    4) 직접 입력 (예: 22,80,443,8000-8100)")
        choice = input(C.W + "  선택 [1] > " + C.END).strip() or "1"
        port_spec = {"1": "top", "2": "1-1024", "3": "all"}.get(choice)
        if port_spec is None:
            port_spec = input(C.W + "  포트 입력 > " + C.END).strip() or "top"

        result = scan_target(target, port_spec, timeout=1.0, workers=200)
        if result:
            _present(result)
        print()


def _present(result):
    ip = result["meta"]["ip"]
    report = build_report(ip, result["meta"], result["open"],
                          result["scanned"], result["elapsed"])
    print("\n" + colorize_report(report))

    if result["open"]:
        nmap = build_nmap_block(ip, result["open"])
        print(C.M + C.BOLD + "\n[ HTML 도구 ⑦ 포트 분석 탭에 붙여넣기용 (nmap 형식) ]" + C.END)
        print(C.G + nmap + C.END)

    # 결과 저장 여부
    try:
        ans = input(C.W + "\n  결과를 파일로 저장할까요? (y/N) > " + C.END).strip().lower()
    except (EOFError, KeyboardInterrupt):
        ans = "n"
    if ans == "y":
        fname = "scan_%s_%s.txt" % (ip.replace(".", "_"),
                                    datetime.now().strftime("%Y%m%d_%H%M%S"))
        save_results(result, fname)
        print(C.G + "  저장됨: %s" % fname + C.END)


def main():
    parser = argparse.ArgumentParser(
        prog=APP_NAME,
        description="nmap 유사 포트 스캐너 - IP 의 포트 개폐/서비스/OS 정보를 확인합니다.")
    parser.add_argument("target", nargs="?",
                        help="스캔 대상 IP 또는 호스트명 (생략 시 대화형 메뉴)")
    parser.add_argument("-p", "--ports", default="top",
                        help="포트 지정: top | all | 1-1024 | 22,80,443 (기본 top)")
    parser.add_argument("-t", "--timeout", type=float, default=1.0,
                        help="포트당 연결 타임아웃 초 (기본 1.0)")
    parser.add_argument("-w", "--workers", type=int, default=200,
                        help="동시 스캔 스레드 수 (기본 200)")
    parser.add_argument("-o", "--output", help="결과를 지정 파일에 저장")
    parser.add_argument("--serve", action="store_true",
                        help="HTML 연동 브리지 서버 모드로 실행")
    parser.add_argument("--serve-host", default="127.0.0.1",
                        help="브리지 서버 바인드 호스트 (기본 127.0.0.1)")
    parser.add_argument("--serve-port", type=int, default=8765,
                        help="브리지 서버 포트 (기본 8765)")
    parser.add_argument("--no-color", action="store_true", help="컬러 출력 끄기")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="진행 표시 없이 결과만 출력")
    parser.add_argument("-V", "--version", action="version",
                        version="%s %s" % (APP_NAME, APP_VERSION))
    args = parser.parse_args()

    if args.no_color:
        C.disable()
    else:
        enable_windows_ansi()

    if args.serve:
        serve_bridge(args.serve_host, args.serve_port)
        return

    if not args.target:
        startup_chooser()
        return

    result = scan_target(args.target, args.ports, args.timeout,
                         args.workers, quiet=args.quiet)
    if not result:
        sys.exit(1)

    report = build_report(result["meta"]["ip"], result["meta"],
                          result["open"], result["scanned"], result["elapsed"])
    print("\n" + (report if args.no_color else colorize_report(report)))
    if result["open"]:
        nmap = build_nmap_block(result["meta"]["ip"], result["open"])
        print("\n[ HTML 도구 ⑦ 포트 분석 탭에 붙여넣기용 (nmap 형식) ]")
        print(nmap if args.no_color else (C.G + nmap + C.END))

    if args.output:
        save_results(result, args.output)
        print("\n저장됨: %s" % args.output)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n중단되었습니다.")
        sys.exit(130)
