import base64
import xml.etree.ElementTree as ET
from vulnman.parsers import core
from urllib.parse import urlparse


VULNERABILITY_MAPPING = {
    "Cross-site scripting": "cross-site-scripting",
    "SQL injection": "sql-injection"
}


class BurpSuitePro(core.ParserPlugin):
    _alias_ = 'burpsuite-pro'
    _version_ = '0.0.1'

    def parse(self, filepath, client):
        root = ET.parse(filepath)
        for issue in root.findall("issue"):
            template_id = VULNERABILITY_MAPPING.get(issue.find("name").text)
            if not template_id:
                continue
            host = self._process_host(issue, client)
            service = self._process_service(host, client)
            vulnerability, created = self._process_vulnerability(issue, service, client)
            # if created:
            self._process_proofs(issue, vulnerability, client)

    def _process_host(self, data, client):
        host = client.add_or_get_host(data.find("host").get("ip"), data.find("host").text)
        return host

    def _process_service(self, host, client):
        if host.get("dns"):
            parsed = urlparse(host["dns"])
            if not parsed.port:
                if parsed.scheme == "https":
                    port = 443
                else:
                    port = 80
            else:
                port = parsed.port
            service = client.add_service(host.get("uuid"), parsed.scheme, port, "tcp")
            return service

    def _process_vulnerability(self, data, service, client):
        # add_vulnerability(self, name, asset, asset_type, template_id, status=2):
        name = data.find("location").text
        asset = service.get("uuid")
        template_id = VULNERABILITY_MAPPING.get(data.find("name").text)
        vuln = client.check_and_get_vulnerability(name, asset, "service", template_id)
        if not vuln:
            vuln = client.add_vulnerability(name, asset, "service", template_id)
            return vuln, True
        return vuln, False

    def _process_proofs(self, data, vulnerability, client):
        print(data.find("issueDetail"))
        if data.find("issueDetail").text:
            desc_proof = client.add_text_proof(vulnerability.get("uuid"), "Details", data.find("issueDetail").text)
        for reqresp in data.findall("requestresponse"):
            req = base64.b64decode(reqresp.find("request").text).decode()
            resp = base64.b64decode(reqresp.find("response").text).decode()
            client.add_text_proof(vulnerability.get("uuid"), "reqeust", "```http\n%s\n```" % req)
            client.add_text_proof(vulnerability.get("uuid"), "response", "```http\n%s\n```" % resp)
