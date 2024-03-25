from cvepackage.CVEHelper import CVE
from cvsspackage.CVSSHelper import CVSSv31Tov4
import requests

cve_id = "CVE-2021-30737"
res = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}").json()
cve = CVE(res)
cve.print_full_report_to_json()
cve4 = CVSSv31Tov4(cve.get_cvss_vector())
