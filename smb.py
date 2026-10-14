"""Conservative SMB service classification from Nmap results."""
def summarize_smb_services(ports):
    candidates = []
    for item in ports:
        service = (item.get("service") or "").lower()
        if item.get("state") == "open" and (
            item.get("port") == 445 or item.get("port") == 139 or "smb" in service
            or "microsoft-ds" in service or "netbios-ssn" in service
        ):
            candidates.append({
                "port": item.get("port"),
                "service": item.get("service"),
                "product": item.get("product"),
                "version": item.get("version"),
                "scripts": item.get("scripts", []),
                "review_status": "candidate",
                "note": "SMB/NetBIOS adayı; ek SMB kontrolleri bu sürümde otomatik çalıştırılmadı."
            })
    return candidates
