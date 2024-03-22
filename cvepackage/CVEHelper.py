from cvepackage.cve_exceptions import CVEMalformedError, CVEMandatoryError, CVEMissingData
import utils.ToFileUtils as tfu


class CVE(object):
    """
    Class to hold CVE data, parsed values, scores and information available through the NVD-NIST API.
    """

    def __init__(self, cve_json: dict):
        """
        Args:
            cve_json (dict): dictionary holding all the data retrieved from the NVD-NIST API
            regarding a single CVE through a cveId lookup call
        """
        self.cve_json = cve_json
        # mandatory data
        self.format = None
        self.cve_id = None
        self.descriptions = []
        # optional data
        self.metrics = {}
        self.weaknesses = []

        self.parse_json()

    def parse_json(self):
        """
        Parses data from the inputted CVE-json data.

        Raises:
            CVEMalformedError: if data is not in expected format
        """
        if self.cve_json == "" or len(self.cve_json.keys()) == 0:
            raise CVEMalformedError("Malformed CVE-json data, json is empty")
        # check for mandatory fields before assignment
        self.check_mandatory()

        self.format = self.cve_json['format']
        cve_data = ((self.cve_json['vulnerabilities'][0])['cve'])
        self.cve_id = cve_data['id']
        self.descriptions = cve_data['descriptions']

        if 'metrics' in cve_data.keys():
            self.metrics = cve_data['metrics']
        if 'weaknesses' in cve_data.keys():
            self.weaknesses = cve_data['weaknesses']

    def try_get_v31_cvss_data(self):
        """
        :returns: a cvssData dict if any v3.1 metrics are available
        """
        if len(self.metrics) > 0 and 'cvssMetricV31' in self.metrics.keys():
            return (self.metrics['cvssMetricV31'][0])['cvssData']

    def get_cvss_vector(self):
        """
        :returns: a CVSS vector string if available
        :raises CVEMissingData: if vector is missing
        """
        cvss_data = self.try_get_v31_cvss_data()
        if len(cvss_data) == 0:
            raise CVEMissingData("Requested cvsspackage data is missing, metrics dict does not contain v3.1 data")
        return cvss_data['vectorString']

    def get_cvss_base_score(self):
        """
        :returns: CVSS base score if available
        :raises CVEMissingData: if base score is missing
        """
        cvss_data = self.try_get_v31_cvss_data()
        if len(cvss_data) == 0:
            raise CVEMissingData("Requested cvsspackage data is missing, metrics dict does not contain v3.1 data")
        return cvss_data['baseScore']

    def get_cvss_severity(self):
        """
        :returns: CVSS base severity if available
        :raises CVEMissingData: if severity score is missing
        """
        cvss_data = self.try_get_v31_cvss_data()
        if len(cvss_data) == 0:
            raise CVEMissingData("Requested cvsspackage data is missing, metrics dict does not contain v3.1 data")
        return cvss_data['baseSeverity']

    def get_exploitability_score(self, vers: float = 3.1):
        """
        Retrieves the CVE CVSS exploitability score based on the given CVSS version (default = 3.1)
        :param vers: chosen version in format M.m (Major.minor)
        :returns: exploitability score if available
        :raises CVEMalformedError: if version is not supported
        :raises CVEMissingData: if any requested data is missing from the CVE json
        """
        if vers == 3.1:
            if 'cvssMetricV31' not in self.metrics.keys():
                raise CVEMissingData("Requested cvsspackage data is missing, metrics dict does not contain v3.1 data")
            cvss_v31_metrics = self.metrics['cvssMetricV31'][0]
            if 'exploitabilityScore' not in cvss_v31_metrics.keys():
                raise CVEMissingData("Requested cvsspackage data is missing, metrics dict does not contain exploitability score")
            return cvss_v31_metrics['exploitabilityScore']
        elif vers == 2.0:
            if 'cvssMetricV2' not in self.metrics.keys():
                raise CVEMissingData("Requested cvsspackage data is missing, metrics dict does not contain v2.0 data")
            cvss_v2_metrics = self.metrics['cvssMetricV2'][0]
            if 'exploitabilityScore' not in cvss_v2_metrics.keys():
                raise CVEMissingData("Requested cvsspackage data is missing, metrics dict does not contain exploitability score")
            return cvss_v2_metrics['exploitabilityScore']
        else:
            raise CVEMalformedError("Requested version is not supported")

    def check_mandatory(self):
        """
        Checks if mandatory fields are in CVE-json data.

        Raises:
            CVEMandatoryError: if mandatory field is missing in the vector
        """
        if not {'format', 'vulnerabilities'}.issubset(self.cve_json.keys()) or 'cve' not in self.cve_json['vulnerabilities'][0].keys():
            raise CVEMandatoryError("Missing mandatory 'format', 'vulnerability' or 'cve' field(s) from CVE-json data")
        if not {'id', 'descriptions'}.issubset(((self.cve_json['vulnerabilities'][0])['cve']).keys()):
            raise CVEMandatoryError("Missing mandatory 'id' or 'descriptions' field(s) from CVE-json data")

    def print_full_report_to_json(self, filename: str = None, filepath: str = "./files/"):
        """
        Desc:
            Prints the entire CVE-json report to a file for quick access and inspection.
        Args:
            filename: the name of the file
            filepath: the destination filepath/folder
        """
        if not filename:
            filename = f"full_{self.cve_id}_report"
        tfu.save_to_json_file(self.cve_json, filename, filepath)
