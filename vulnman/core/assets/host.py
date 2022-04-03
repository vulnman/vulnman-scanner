import asyncio


class Host:
    def __init__(self, ip, address, autorecon):
        self.address = address
        self.ip = ip
        self.autorecon = autorecon
        self.base_dir = ''
        self.scan_dir = ''
        self.report_dir = ''
        self.ports = None
        self.pending_services = []
        self.services = []
        self.scans = {'ports': {}, 'services': {}}
        self.running_tasks = {}
        self.lock = asyncio.Lock()

    async def add_service(self, service):
        async with self.lock:
            self.pending_services.append(service)
