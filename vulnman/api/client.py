import requests


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
            resp = self.session.post(
                url, json=data, headers=self.get_headers())
        else:
            resp = self.session.post(
                url, data=data, headers=self.get_headers())
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
        endpoint = "/api/v1/agents/hosts/"
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
        endpoint = "/api/v1/agents/services/"
        resp = self._post(endpoint, payload)
        if resp.status_code not in [200, 201]:
            raise UnexpectedStatusCode(resp.json())
        return resp.json()

    def create_vulnerability(self, name, asset, asset_type, template_id, status=2):
        payload = {
            "asset": asset, "asset_type": asset_type,
            "template_id": template_id, "status": status, "name": name
        }
        endpoint = "/api/v1/agents/vulnerabilities/"
        resp = self._post(endpoint, payload)
        if resp.status_code not in [200, 201]:
            raise UnexpectedStatusCode(resp.json())
        return resp.json()

    def create_text_proof(self, vulnerability_id, name, text, description=None, order=None):
        endpoint = "/api/v1/agents/text-proofs/"
        payload = {
            "vulnerability": vulnerability_id, "name": name,
            "text": text, "description": description
        }
        resp = self._post(endpoint, payload)
        if resp.status_code not in [200, 201]:
            raise UnexpectedStatusCode(resp.json())
        return resp.json()
