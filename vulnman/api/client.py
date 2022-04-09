import requests
import re


class UnexpectedStatusCode(Exception):
    pass


class Client(object):
    def __init__(self, base_url, token, *args, **kwargs):
        self._headers = {}
        self.token = token
        self.session = requests.Session()
        self.base_url = base_url

    def _get(self, endpoint):
        url = "%s%s" % (self.base_url, endpoint)
        resp = self.session.get(url, headers=self.get_headers())
        return resp

    def _post(self, endpoint, data, as_json=True):
        url = "%s%s" % (self.base_url, endpoint)
        if as_json:
            resp = self.session.post(url, json=data, headers=self.get_headers())
        else:
            resp = self.session.post(url, data=data, headers=self.get_headers())
        return resp

    def get_headers(self):
        if not self._headers.get('Authorization'):
            self._headers["Authorization"] = "Token %s" % self.token
        return self._headers


class VulnmanClient(Client):
    def create_host(self, ip, dns=None, accessibility=None):
        payload = {"ip": ip, "dns": dns}
        if accessibility:
            payload["accessbility"] = accessibility
        endpoint = "/api/v2/hosts/"
        resp = self._post(endpoint, payload)
        if resp.status_code not in [200, 201]:
            raise UnexpectedStatusCode(resp.json())
        return resp.json()

    def create_service(self, host_id, name, port, protocol, state=None):
        payload = {
            "host": host_id, "name": name, "port": port,
            "protocol": protocol}
        if state:
            payload["state"] = state
        endpoint = "/api/v2/services/"
        resp = self._post(endpoint, payload)
        if resp.status_code not in [200, 201]:
            raise UnexpectedStatusCode(resp.json())
        return resp.json()

    def create_vulnerability(self, name, asset, asset_type, template_id, status=2):
        payload = {
            "asset": asset, "asset_type": asset_type,
            "template_id": template_id, "status": status, "name": name
        }
        endpoint = "/api/v2/vulnerabilities/"
        resp = self._post(endpoint, payload)
        if resp.status_code not in [200, 201]:
            raise UnexpectedStatusCode(resp.json())
        return resp.json()

    def create_text_proof(self, vulnerability_id, name, text, description=None, order=None):
        endpoint = "/api/v2/text-proofs/"
        payload = {
            "vulnerability": vulnerability_id, "name": name,
            "text": text, "description": description
        }
        resp = self._post(endpoint, payload)
        if resp.status_code not in [200, 201]:
            raise UnexpectedStatusCode(resp.json())
        return resp.json()


class VulnmanClient2(Client):
    active_project = None

    def activate_project(self, project_id):
        self.active_project = project_id

    def get_active_project(self):
        if not self.active_project:
            raise Exception("No active project found!")
        return self.active_project

    def add_or_get_host(self, ip, dns=None, accessibility=None):
        payload = {"ip": ip, "project": self.get_active_project(), "dns": dns}
        endpoint = "/api/v1/assets/hosts/"
        resp = self._post(endpoint, payload)
        if not resp.status_code == 201:
            if resp.status_code == 400 and "unique set" in str(resp.json()):
                resp = self._get("/api/v1/projects/%s/" % self.get_active_project())
                for host in resp.json()["assets_host"]:
                    if host["ip"] == ip:
                        return host
            raise UnexpectedStatusCode(resp.json())
        return resp.json()

    def add_service(self, host_id, name, port, protocol, state="open"):
        payload = {"host": host_id, "name": name, "port": port, "protocol": protocol, "state": state,
                   "project": self.get_active_project()}
        endpoint = "/api/v1/assets/services/"
        resp = self._post(endpoint, payload)
        if not resp.status_code == 201:
            if resp.status_code == 400 and "unique set" in str(resp.json()):
                resp = self._get("/api/v1/projects/%s/" % self.get_active_project())
                for service in resp.json()["assets_service"]:
                    if service["port"] == port and service["host"] == host_id and service["protocol"] == protocol:
                        return service
            raise UnexpectedStatusCode(resp.json())
        return resp.json()

    def add_vulnerability(self, name, asset, asset_type, template_id, status=2):
        payload = {"asset": asset, "asset_type": asset_type, "template_id": template_id,
                   "status": status, "name": name, "project": self.get_active_project()}
        endpoint = "/api/v1/vulnerabilities/"
        resp = self._post(endpoint, payload)
        if not resp.status_code == 201:
            raise UnexpectedStatusCode(resp.text[:6000])
        return resp.json()

    def check_and_get_vulnerability(self, name, asset, asset_type, template_id):
        resp = self._get("/api/v1/projects/%s/" % self.get_active_project())
        if resp.status_code != 200:
            raise UnexpectedStatusCode()
        for vuln in resp.json().get("vulnerabilities", []):
            if vuln["name"] == name and asset_type == vuln["asset_type"] and asset == vuln["asset"] and template_id == \
                    vuln["template_id"]:
                return vuln
        return None

    def add_text_proof(self, vulnerability_id, name, text, description=None, order=None):
        endpoint = "/api/v1/vulnerabilities/text-proof/"
        payload = {"vulnerability": vulnerability_id, "name": name, "text": text,
                   "project": self.get_active_project(), "description": description}
        resp = self._post(endpoint, payload)
        if not resp.status_code == 201:
            raise UnexpectedStatusCode(resp.text[:6000])
        return resp.json()
