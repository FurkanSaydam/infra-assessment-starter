"""Conservative classification of web-like services; sends no extra requests."""
WEB_PORTS = {80, 81, 443, 444, 591, 593, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000}

def summarize_web_services(ports):
    result = []
    for item in ports or []:
        service = (item.get("service") or "").lower()
        if item.get("state") == "open" and (item.get("port") in WEB_PORTS or "http" in service):
            result.append({"port": item.get("port"), "service": item.get("service"),
                           "product": item.get("product"), "version": item.get("version"),
                           "review_status": "candidate",
                           "note": "Web servisi adayı; bu modül aktif HTTP güvenlik testi yapmadı."})
    return result
