import json
import os
from vulnman.scanner.plugins import core as plugins


class Corsy(plugins.ServiceScanPlugin):
    _alias_ = "corsy"
    _version_ = '0.0.1'
    _tags = ["http", "safe", "default"]
    toolnames = ["corsy"]

    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)

    async def run(self, service):
        cmd = "corsy -u {http_scheme}://{address}:{port} -o {scandir}/{protocol}{port}/corsy.json"
        await service.execute(self, cmd)

    async def on_plugin_end(self, output, cmd, target=None, service=None):
        result_file = service.parse_string_vals(
            "{scandir}/{protocol}{port}/corsy.json")
        if not os.path.exists(result_file):
            return
        with open(result_file, "r") as f:
            results = json.load(f)
        cmd = service.parse_string_vals(
            "corsy -u {http_scheme}://{address}:{port}")
        for result in results.keys():
            text_proof = "```json\n$ %s\n[...]\n" % cmd
            text_proof += "%s" % json.dumps(results[result], indent=4)
            text_proof += "\n[...]\n```"
            proof = self.get_proof_from_data(cmd, text_proof)
            proof.set_description(results[result].get("description"))
            service.add_vulnerability(
                "cors-misconfig", [proof], self)
