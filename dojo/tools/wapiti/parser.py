from xml.dom import NamespaceErr
import hashlib
from urllib.parse import urlparse
import re
from defusedxml import ElementTree as ET
from dojo.models import Endpoint, Finding

__author__ = 'dr3dd589'


class Severityfilter():
    def __init__(self):
        self.severity_mapping = {'4': 'Info',
                                 '3': 'Low',
                                 '2': 'Medium',
                                 '1': 'High'
                                 }
        self.severity = None

    def eval_column(self, column_value):
        if column_value in list(self.severity_mapping.keys()):
            self.severity = self.severity_mapping[column_value]
        else:
            self.severity = 'Info'


class WapitiXMLParser(object):
    def __init__(self, file, test):
        self.dupes = dict()
        self.items = ()
        if file is None:
            return

        tree = ET.parse(file)
        # get root of tree.
        root = tree.getroot()
        # check if it is
        if 'report' not in root.tag:
            raise NamespaceErr("This doesn't seem to be a valid Wapiti xml file.")

        for child in root:
        # host is now separate from vulnerability elements
        if child.tag == 'report_infos':
            for item in child:
                for v in item.attrib.values():
                    if v == 'target':
                        # get host
                        host = item.text
        # parsing the vulnerabilities
        if child.tag == 'vulnerabilities':
            for item in child:
                # get risk title
                title = item.attrib['name']
                for el in item:
                    # get description
                    if el.tag == 'description':
                        description = el.text
                    # get mitigation
                    if el.tag == 'solution':
                        mitigation = el.text
                    # get references
                    if el.tag == 'references':
                        reference = el.text
                # Wapiti XML reports have none of this information below
                cve = 'N/A'
                severity = 'N/A'
                num_severity = 'N/A'
                impact = 'N/A'
                # make dupe hash key
                dupe_key = hashlib.md5(str(description + title + severity).encode('utf-8')).hexdigest()
                # check if dupes are present
                if dupe_key in self.dupes:
                    finding = self.dupes[dupe_key]
                    if finding.description:
                        finding.description = finding.description
                    self.process_endpoints(finding, host)
                    self.dupes[dupe_key] = finding
                else:
                    self.dupes[dupe_key] = True
                    
                    finding = Finding(title=title,
                                    test=test,
                                    active=False,
                                    verified=False,
                                    cve=cve,
                                    description=description,
                                    severity=severity,
                                    numerical_severity=num_severity,
                                    mitigation=mitigation,
                                    impact=impact,
                                    references=reference,
                                    dynamic_finding=True)
                    self.dupes[dupe_key] = finding
                    self.process_endpoints(finding, host)

            self.items = list(self.dupes.values())

    def process_endpoints(self, finding, host):
        protocol = "http"
        query = ""
        fragment = ""
        path = ""
        url = urlparse(host)

        if url:
            path = url.path
            if path == host:
                path = ""

        rhost = re.search(
            r"(http|https|ftp)\://([a-zA-Z0-9\.\-]+(\:[a-zA-Z0-9\.&amp;%\$\-]+)*@)*((25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])|localhost|([a-zA-Z0-9\-]+\.)*[a-zA-Z0-9\-]+\.(com|edu|gov|int|mil|net|org|biz|arpa|info|name|pro|aero|coop|museum|[a-zA-Z]{2}))[\:]*([0-9]+)*([/]*($|[a-zA-Z0-9\.\,\?\'\\\+&amp;%\$#\=~_\-]+)).*?$",
            host)
        try:
            protocol = rhost.group(1)
            host = rhost.group(4)
        except:
            pass
        try:
            dupe_endpoint = Endpoint.objects.get(protocol=protocol,
                                                 host=host,
                                                 query=query,
                                                 fragment=fragment,
                                                 path=path
                                                 )
        except Endpoint.DoesNotExist:
            dupe_endpoint = None

        if not dupe_endpoint:
            endpoint = Endpoint(protocol=protocol,
                                host=host,
                                query=query,
                                fragment=fragment,
                                path=path
                                )
        else:
            endpoint = dupe_endpoint

        if not dupe_endpoint:
            endpoints = [endpoint]
        else:
            endpoints = [endpoint, dupe_endpoint]

        finding.unsaved_endpoints = finding.unsaved_endpoints + endpoints
