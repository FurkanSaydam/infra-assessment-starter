"""Conservative SMB classification; no credentials or intrusive checks."""
def summarize_smb_services(ports):
    result = []
    for item in ports or []:
        service = (item.get("service") or "").lower()
        if item.get("state") == "open" and (item.get("port") in (139, 445) or
                "smb" in service or "microsoft-ds" in service or "netbios-ssn" in service):
            result.append({"port": item.get("port"), "service": item.get("service"),
                           "product": item.get("product"), "version": item.get("version"),
                           "scripts": item.get("scripts", []), "review_status": "candidate",
                           "note": "SMB/NetBIOS adayı; ek SMB kontrolleri otomatik çalıştırılmadı."})
    return result
