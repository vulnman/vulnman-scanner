import asyncio, inspect, os
from typing import final
from vulnman.core.utils.logging import logger
from autorecon.io import e


class Target:

	def __init__(self, address, ip, ipversion, type, autorecon):
		self.address = address
		self.ip = ip
		self.ipversion = ipversion
		self.type = type
		self.autorecon = autorecon
		self.basedir = ''
		self.reportdir = ''
		self.scandir = ''
		self.lock = asyncio.Lock()
		self.ports = None
		self.pending_services = []
		self.services = []
		self.scans = {'ports': {}, 'services': {}}
		self.running_tasks = {}

	def parse_string_vals(self, d):
		d = d.format(
			address=self.address, scandir=self.scandir, ip=self.ip,
			reportdir=self.reportdir, basedir=self.basedir, ipversion=self.ipversion
		)
		return d

	async def add_service(self, service):
		async with self.lock:
			self.pending_services.append(service)

	@final
	def info(self, msg, verbosity=0):
		plugin = inspect.currentframe().f_back.f_locals['self']
		logger.info('{bright}[{yellow}' + self.address + '{crst}/{bgreen}' + plugin.slug + '{crst}]{rst} ' + msg)

	@final
	def warn(self, msg, verbosity=0):
		plugin = inspect.currentframe().f_back.f_locals['self']
		logger.warn('{bright}[{yellow}' + self.address + '{crst}/{bgreen}' + plugin.slug + '{crst}]{rst} ' + msg)

	@final
	def error(self, msg, verbosity=0):
		plugin = inspect.currentframe().f_back.f_locals['self']
		logger.error('{bright}[{yellow}' + self.address + '{crst}/{bgreen}' + plugin.slug + '{crst}]{rst} ' + msg)

	async def execute(self, cmd, blocking=True, outfile=None, errfile=None, future_outfile=None):
		target = self

		# Create variables for command references.
		address = target.address
		addressv6 = target.address
		ipaddress = target.ip
		ipaddressv6 = target.ip
		scandir = target.scandir

		nmap_extra = target.autorecon.args.nmap
		if target.autorecon.args.nmap_append:
			nmap_extra += ' ' + target.autorecon.args.nmap_append

		if target.ipversion == 'IPv6':
			nmap_extra += ' -6'
			if addressv6 == target.ip:
				addressv6 = '[' + addressv6 + ']'
			ipaddressv6 = '[' + ipaddressv6 + ']'

		plugin = inspect.currentframe().f_back.f_locals['self']

		cmd = e(cmd)
		tag = plugin.slug

		logger.info('Port scan {bblue}' + plugin.name + ' {green}(' + tag + '){rst} is running the following command against {byellow}' + address + '{rst}: ' + cmd, verbosity=2)

		if outfile is not None:
			outfile = os.path.join(target.scandir, e(outfile))

		if errfile is not None:
			errfile = os.path.join(target.scandir, e(errfile))

		if future_outfile is not None:
			future_outfile = os.path.join(target.scandir, e(future_outfile))

		target.scans['ports'][tag]['commands'].append([cmd, outfile if outfile is not None else future_outfile, errfile])

		async with target.lock:
			with open(os.path.join(target.scandir, '_commands.log'), 'a') as file:
				file.writelines(cmd + '\n\n')

		process, stdout, stderr = await target.autorecon.execute(cmd, target, tag, plugin, outfile=outfile, errfile=errfile)

		target.running_tasks[tag]['processes'].append({'process': process, 'stderr': stderr, 'cmd': cmd})

		# If process should block, sleep until stdout and stderr have finished.
		if blocking:
			while not (stdout.ended and stderr.ended):
				await asyncio.sleep(0.1)
			await process.wait()
		return process, stdout, stderr
