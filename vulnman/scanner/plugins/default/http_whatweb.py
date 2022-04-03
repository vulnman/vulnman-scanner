import json
import os
from vulnman.scanner.plugins import core as plugins


class Whatweb(plugins.ServiceScanPlugin):
    _alias_ = 'whatweb'
    _version_ = '0.0.1'
    _tags = ["default", "safe", "http"]

    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)

    async def run(self, service):
        if service.protocol == 'tcp' and service.target.ipversion == 'IPv4':
            result_file = "{scandir}/{protocol}{port}/{protocol}_{port}_{http_scheme}_whatweb.json"
            if os.path.exists(service.parse_string_vals(result_file)):
                os.remove(service.parse_string_vals(
                    "{scandir}/{protocol}{port}/{protocol}_{port}_{http_scheme}_whatweb.json"))
            cmd = "whatweb --color=never --no-errors -a 3 -v {http_scheme}://{address}:{port} " \
                  "--log-json={scandir}/{protocol}{port}/{protocol}_{port}_{http_scheme}_whatweb.json"
            await service.execute(self, cmd)

    async def on_plugin_end(self, output, cmd, target=None, service=None):
        result_file = service.parse_string_vals(
            "{scandir}/{protocol}{port}/{protocol}_{port}_{http_scheme}_whatweb.json")
        with open(result_file, "r") as f:
            results = json.loads(f.read())
            for result in results:
                for plugin_name, plugin in result.get('plugins', {}).items():
                    proofs = []
                    for version in plugin.get('version', []):
                        data = "```bash\n$ %s\n```" % service.parse_string_vals(
                            "whatweb --color=never --no-errors -a 3 -v {http_scheme}://{address}:{port}")
                        proof = self.get_proof_from_data(cmd, data)
                        proof.set_description("The software *%s* was found in version *%s*." % (plugin_name, version))
                        proofs.append(proof)
                    if proofs:
                        service.add_vulnerability("version_info", proofs, self, name=plugin_name)
