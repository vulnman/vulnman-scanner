import asyncio
from datetime import datetime
from vulnman.config import config
from vulnman.core.utils.logging import logger


async def start_heartbeat(target, period=60):
    while True:
        await asyncio.sleep(period)
        async with target.lock:
            count = len(target.running_tasks)

            tasks_list = ''
            if config['verbose'] >= 1:
                tasks_list = ': {bblue}' + ', '.join(target.running_tasks.keys()) + '{rst}'

            current_time = datetime.now().strftime('%H:%M:%S')

            if count > 1:
                logger.info('{bgreen}' + current_time + '{rst} - There are {byellow}' + str(
                    count) + '{rst} scans still running against {byellow}' + target.address + '{rst}' + tasks_list)
            elif count == 1:
                logger.info(
                    '{bgreen}' + current_time + '{rst} - There is {byellow}1{rst} scan still running against '
                                                '{byellow}' + target.address + '{rst}' + tasks_list)
