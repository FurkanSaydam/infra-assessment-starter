"""Conservative defaults for the starter project."""
APP_NAME = "Scoped Infrastructure Assessment"
APP_VERSION = "0.1.0"
DEFAULT_PROFILE = "safe"
DEFAULT_TIMEOUT_SECONDS = 900
DEFAULT_TOP_PORTS = 1000
NMAP_BINARY = "nmap"

# This product intentionally does not auto-run broad NSE categories such as
# vuln, exploit, intrusive, http*, or smb*. Review and enable checks deliberately.
