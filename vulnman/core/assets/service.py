import os
import asyncio
from vulnman.core.assets.vulnerability import Vulnerability
from vulnman.core.utils.logging import logger


class Service(object):
    def __init__(self, protocol, port, name, secure=False):
        self.target = None
        self.protocol = protocol.lower()
        self.port = int(port)
        self.name = name
        self.secure = secure
        self.vulnerabilities = []

    @property
    def tag(self):
        return "%s/%s/%s" % (self.protocol, self.port, self.name)

    @property
    def full_tag(self):
        return self.protocol + '/' + str(self.port) + '/' + self.name + '/' + ('secure' if self.secure else 'insecure')

    @property
    def http_scheme(self):
        if "https" in self.name:
            return "https"
        if self.secure:
            return "https"
        return "http"

    def get_scan_dir(self):
        return self.target.scandir

    def parse_string_vals(self, d):
        d = d.format(
            http_scheme=self.http_scheme, address=self.target.address,
            scandir=self.target.scandir, addressv6=self.target.address,
            port=self.port, protocol=self.protocol
        )
        return d

    async def execute(self, plugin, command, blocking=True, outfile=None, errfile=None, future_outfile=None):
        nmap_extra = self.target.autorecon.args.nmap
        if self.target.autorecon.args.nmap_append:
            nmap_extra += ' ' + self.target.autorecon.args.nmap_append
        if self.protocol == "udp":
            nmap_extra += " -sU"

        if outfile is not None:
            outfile = os.path.join(self.get_scan_dir(), self.parse_string_vals(outfile))
        if errfile is not None:
            errfile = os.path.join(self.get_scan_dir(), self.parse_string_vals(errfile))
        if future_outfile is not None:
            future_outfile = os.path.join(self.get_scan_dir(), self.parse_string_vals(future_outfile))

        cmd = self.parse_string_vals(command)

        tag = self.tag + '/' + plugin.slug
        plugin_tag = tag
        if plugin.run_once_boolean:
            plugin_tag = plugin.slug

        logger.info(
            'Service scan {bblue}' + plugin.name +
            ' {green}(' + tag + '){rst} is running the following command against {byellow}' +
            self.target.address + '{rst}: ' + cmd)

        self.target.scans["services"][self][plugin_tag]['commands'].append(
            [cmd, outfile if outfile is not None else future_outfile, errfile]
        )

        async with self.target.lock:
            with open(os.path.join(self.get_scan_dir(), '_commands.log'), 'a') as f:
                f.writelines(cmd + "\n\n")

        process, stdout, stderr = await self.target.autorecon.execute(
            cmd, self.target, tag, plugin, service=self, outfile=outfile, errfile=errfile
        )
        self.target.running_tasks[tag]["processes"].append({'process': process, 'stderr': stderr, 'cmd': cmd})

        # If process should block, sleep until stdout and stderr have finished.
        if blocking:
            while not (stdout.ended and stderr.ended):
                await asyncio.sleep(0.1)
            await process.wait()
        return process, stdout, stderr

    def add_vulnerability(self, vuln_id, proofs, plugin, name=None):
        vuln_exists = False
        for vuln in self.vulnerabilities:
            if vuln.vuln_id == vuln_id and vuln.name == name:
                vuln_exists = True
                for proof in proofs:
                    vuln.add_proof(proof)
                break
        if not vuln_exists:
            vuln = Vulnerability(vuln_id, plugin.autorecon, name=name)
            for proof in proofs:
                vuln.add_proof(proof)
            self.vulnerabilities.append(vuln)
            logger.info("{bmagenta}[Vulnerability found]{rst} {byellow}%s{rst} by plugin %s" % (
                vuln.name, proofs[0].plugin.name))
            return vuln
