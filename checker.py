import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse
import requests

# الترويسات الأمنية المطلوب فحصها وأهميتها وتوصية إصلاحها
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "weight": 20,
        "risk": "يسمح بهجمات خفض البروتوكول (SSL Stripping) والتنصت.",
        "fix": "أضف: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    },
    "Content-Security-Policy": {
        "weight": 25,
        "risk": "يزيد احتمالية نجاح هجمات حقن الأكواد (XSS).",
        "fix": "حدد مصادر المحتوى الموثوقة عبر ترويسة Content-Security-Policy."
    },
    "X-Frame-Options": {
        "weight": 15,
        "risk": "يعرّض الموقع لهجمات الاختطاف بالنقر (Clickjacking).",
        "fix": "أضف: X-Frame-Options: DENY أو SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "weight": 15,
        "risk": "يسمح للمتصفح بتخمين نوع الملفات (MIME Sniffing).",
        "fix": "أضف: X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "weight": 15,
        "risk": "قد تتسرب روابط حساسة في ترويسة Referer عند الانتقال لمواقع خارجية.",
        "fix": "أضف: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "weight": 10,
        "risk": "لا يقيد وصول المتصفح للكاميرا أو الميكروفون أو الموقع الجغرافي.",
        "fix": "أضف: Permissions-Policy: geolocation=(), microphone=(), camera=()"
    }
}


def normalize_url(target: str) -> str:
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target


def check_ssl(hostname: str, port: int = 443) -> dict:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                issuer = dict(x[0] for x in cert.get("issuer", []))
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (not_after - datetime.now(timezone.utc)).days

                return {
                    "valid": True,
                    "protocol": protocol,
                    "issuer": issuer.get("organizationName", "Unknown"),
                    "expires_in_days": days_left
                }
    except Exception as e:
        return {"valid": False, "error": str(e)}


def check_headers(url: str) -> dict:
    try:
        response = requests.get(url, timeout=8, allow_redirects=True)
        headers = {k.lower(): v for k, v in response.headers.items()}
        score = 0
        results = []

        for header, info in SECURITY_HEADERS.items():
            present = header.lower() in headers
            if present:
                score += info["weight"]
            results.append({
                "header": header,
                "present": present,
                "value": headers.get(header.lower(), "غير موجود"),
                "risk": info["risk"],
                "fix": info["fix"]
            })

        return {
            "success": True,
            "final_url": response.url,
            "status_code": response.status_code,
            "score": score,
            "details": results
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_grade(score: int, ssl_valid: bool) -> str:
    if not ssl_valid:
        return "F (خطر مرتفع - شهادة SSL غير صالحة)"
    if score >= 90:
        return "A (ممتاز)"
    elif score >= 75:
        return "B (جيد)"
    elif score >= 50:
        return "C (متوسط - يحتاج تحسين)"
    return "D (ضعيف)"


def run_audit(target: str):
    url = normalize_url(target)
    hostname = urlparse(url).hostname

    print("=" * 60)
    print(f"تقرير الفحص الأمني للموقع: {url}")
    print("=" * 60)

    # 1. فحص SSL/TLS
    ssl_res = check_ssl(hostname)
    print("\n[1] حالة شهادة SSL/TLS:")
    if ssl_res["valid"]:
        print(f"  - الحالة: صالحة (Valid)")
        print(f"  - البروتوكول المستخدم: {ssl_res['protocol']}")
        print(f"  - الجهة المُصدِرة: {ssl_res['issuer']}")
        print(f"  - الأيام المتبقية للانتهاء: {ssl_res['expires_in_days']} يوم")
    else:
        print(f"  - تحذير: فشل التحقق من الشهادة ({ssl_res['error']})")

    # 2. فحص الترويسات الأمنية
    hdr_res = check_headers(url)
    if not hdr_res["success"]:
        print(f"\n[!] تعذر الاتصال بالموقع: {hdr_res['error']}")
        return

    print(f"\n[2] فحص ترويسات HTTP الأمنية (كود الاستجابة: {hdr_res['status_code']}):")
    for item in hdr_res["details"]:
        status_icon = "[✔]" if item["present"] else "[✘]"
        print(f"  {status_icon} {item['header']}: {item['value']}")

    # 3. التوصيات والنتيجة النهائية
    missing = [d for d in hdr_res["details"] if not d["present"]]
    if missing:
        print("\n[3] التوصيات الأمنية لمعالجة الثغرات المكتشفة:")
        for m in missing:
            print(f"  * {m['header']}:")
            print(f"    - الخطر: {m['risk']}")
            print(f"    - الحل: {m['fix']}")

    grade = get_grade(hdr_res["score"], ssl_res["valid"])
    print("\n" + "=" * 60)
    print(f"النتيجة النهائية: {hdr_res['score']}/100  |  التقييم: {grade}")
    print("=" * 60)


if __name__ == "__main__":
    site = input("أدخل رابط الموقع للفحص (مثال: example.com): ")
    run_audit(site)
