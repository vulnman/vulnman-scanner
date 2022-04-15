import os
from vulnman.scanner.plugins import core as plugins
from vulnman.core.utils.logging import logger
from vulnman.config import config


class Markdown(plugins.ReportPlugin):
    _alias_ = "markdown"
    _version_ = "0.0.1"

    async def run(self, targets):
        if len(targets) > 1:
            report = os.path.join(config["output"], "report.md")
        elif len(targets) == 1:
            report = os.path.join(targets[0].reportdir, "report.md")
        else:
            logger.warn("No targets found!")
            return None
        os.makedirs(report, exist_ok=True)

        for target in targets:
            target_dir = os.path.join(report, target.address)
            os.makedirs(target_dir, exist_ok=True)
            for service in target.scans.get("services", {}).keys():
                if not service.vulnerabilities:
                    continue
                service_dir = os.path.join(target_dir, "%s%s" % (service.protocol, service.port))
                os.makedirs(service_dir, exist_ok=True)
                for vuln in service.vulnerabilities:
                    vuln_md = "# %s\n" % vuln.name
                    vuln_md += "## Proofs\n"
                    for proof in vuln.proofs:
                        vuln_md += "%s\n%s\n" % (proof.description, proof.text_proof)
                    with open(os.path.join(service_dir, vuln.name), "w") as f:
                        f.write(vuln_md)
