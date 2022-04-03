import traceback
import sys
from vulnman.core.utils import logger


async def generate_report(vulnman_scanner, plugin, targets):

    #if not config['force_services']:
    #    semaphore = await get_semaphore(autorecon)
    async with vulnman_scanner.service_scan_semaphore:
        try:
            await plugin.run(targets)
        except Exception as ex:
            exc_type, exc_value, exc_tb = sys.exc_info()
            error_text = ''.join(traceback.format_exception(exc_type, exc_value, exc_tb)[-2:])
            logger.error("Report plugin {BBLUE}" + plugin.name + " {GREEN}(" + plugin.slug +
                         "){RST} produced an exception:\n\n" + error_text)
            raise Exception(error_text)
