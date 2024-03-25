from cvepackage.cve_exceptions import CVEMalformedError, CVEMandatoryError, CVEMissingData
import utils.ToFileUtils as tfu


def _try_get_v31_cvss_metric(metrics: dict) -> dict:
    """
    :returns: a cvss metric dict if any is available
    :raises CVEMissingData if the requested data is not available
    """
    if len(metrics) > 0 and 'cvssMetricV31' in metrics.keys():
        return metrics['cvssMetricV31'][0]
    else:
        raise CVEMissingData("Requested cvss metric is missing, metrics dict does not contain v31 metrics")


def _try_get_v2_cvss_metric(metrics: dict) -> dict:
    """
    :returns: a cvss metric dict if any is available
    :raises CVEMissingData if the requested data is not available
    """
    if len(metrics) > 0 and 'cvssMetricV2' in metrics.keys():
        return metrics['cvssMetricV2'][0]
    else:
        raise CVEMissingData("Requested cvss metric is missing, metrics dict does not contain v2 metrics")


def _try_get_v31_cvss_data(metrics: dict) -> dict:
    """
    :returns: a cvssData dict if any v3.1 metrics are available
    :raises CVEMissingData if the requested data is not available
    """
    if len(metrics) > 0 and 'cvssMetricV31' in metrics.keys():
        return (metrics['cvssMetricV31'][0])['cvssData']
    else:
        raise CVEMissingData("Requested cvss data is missing, metrics dict does not contain v3.1 data")


def _try_get_v2_cvss_data(metrics: dict) -> dict:
    """
    :returns: a cvssData dict if any v2 metrics are available
    :raises CVEMissingData if the requested data is not available
    """
    cvss_metric = _try_get_v2_cvss_metric(metrics)
    if 'cvssData' in cvss_metric.keys():
        return cvss_metric['cvssData']
    else:
        raise CVEMissingData("Requested cvss data is missing, metrics dict does not contain v2 data")


class CVE(object):
    """
    Class to hold CVE data, parsed values, scores and information available through the NVD-NIST API.
    """

    __supported_vers = {3.1: [_try_get_v31_cvss_metric, _try_get_v31_cvss_data],
                        2.0: [_try_get_v2_cvss_metric, _try_get_v2_cvss_data]}

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

    def get_cvss_vector(self, vers: float = 3.1) -> str:
        """
        :param vers: chosen version in format M.m (Major.minor)
        :returns: a CVSS vector string for the specified version if available
        :raises CVEMalformedError: if version is not supported
        :raises CVEMissingData: if the cvss string is missing
        """
        if vers not in self.__supported_vers.keys():
            raise CVEMalformedError("Requested version is not supported")

        cvss_data = self.__supported_vers[vers][1](self.metrics)
        if 'vectorString' in cvss_data.keys():
            return cvss_data['vectorString']
        else:
            raise CVEMissingData("Requested cvss string is missing")

    def get_cvss_base_score(self, vers: float = 3.1) -> float:
        """
        :param vers: chosen version in format M.m (Major.minor)
        :returns: CVSS base score if available
        :raises CVEMalformedError: if version is not supported
        :raises CVEMissingData: if the cvss base score is missing
        """
        if vers not in self.__supported_vers.keys():
            raise CVEMalformedError("Requested version is not supported")

        cvss_data = self.__supported_vers[vers][1](self.metrics)
        if 'baseScore' in cvss_data.keys():
            return cvss_data['baseScore']
        else:
            raise CVEMissingData("Requested cvss base score is missing")

    def get_cvss_severity(self, vers: float = 3.1) -> float:
        """
        :param vers: chosen version in format M.m (Major.minor)
        :returns: CVSS base severity if available
        :raises CVEMalformedError: if version is not supported
        :raises CVEMissingData: if the cvss severity is missing
        """
        if vers not in self.__supported_vers.keys():
            raise CVEMalformedError("Requested version is not supported")

        cvss_data = self.__supported_vers[vers][1](self.metrics)
        # exception for v2 which has basSeverity in metrics
        if vers == 2.0:
            cvss_data = self.__supported_vers[vers][0](self.metrics)

        if 'baseSeverity' in cvss_data.keys():
            return cvss_data['baseSeverity']
        else:
            raise CVEMissingData("Requested cvss severity is missing")

    def get_exploitability_score(self, vers: float = 3.1) -> float:
        """
        Retrieves the CVE CVSS exploitability score based on the given CVSS version (default = 3.1)
        :param vers: chosen version in format M.m (Major.minor)
        :returns: exploitability score if available
        :raises CVEMalformedError: if version is not supported
        :raises CVEMissingData: if any requested data is missing from the CVE json
        """
        if vers not in self.__supported_vers.keys():
            raise CVEMalformedError("Requested version is not supported")

        cvss_metric = self.__supported_vers[vers][0](self.metrics)
        if 'exploitabilityScore' in cvss_metric:
            return cvss_metric['exploitabilityScore']
        else:
            raise CVEMissingData("Requested cvss data is missing, metrics dict does not contain exploitability score")

    def check_mandatory(self):
        """
        Checks if mandatory fields are in CVE-json data.

        Raises:
            CVEMandatoryError: if mandatory field is missing in the vector
        """
        if not {'format', 'vulnerabilities'}.issubset(self.cve_json.keys()) or 'cve' not in \
                self.cve_json['vulnerabilities'][0].keys():
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
