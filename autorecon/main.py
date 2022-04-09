#!/usr/bin/python3

import argparse, asyncio, inspect, ipaddress, math, os, re, signal, socket, sys, termios, \
    time, traceback, tty

try:
    import colorama
    from colorama import Fore
    import yaml
except ModuleNotFoundError:
    print('One or more required modules was not installed. Please run or re-run: ' + (
        'sudo ' if os.getuid() == 0 else '') + 'python3 -m pip install -r requirements.txt')
    sys.exit(1)

from autorecon.config import config, configurable_keys, configurable_boolean_keys
from autorecon.targets import Target
from vulnman.core import assets
from vulnman.core.utils.io import e
from vulnman.core.utils.slugify import slugify
from vulnman.core.utils.logging import logger
from vulnman.scanner.plugins.core import PortScanPlugin, ServiceScanPlugin
from vulnman.scanner.utils import tasks as task_utils
from vulnman.scanner import tasks
from vulnman.scanner.vulnscanner import VulnmanScanner


VERSION = "0.0.1"

colorama.init()

# Save current terminal settings so we can restore them.
terminal_settings = termios.tcgetattr(sys.stdin.fileno())

autorecon = VulnmanScanner()
autorecon.import_vulnerability_templates()
logger.info(
    "Loaded %s vulnerability templates!" % len(
        autorecon.vulnerability_templates))


async def get_semaphore(autorecon):
    semaphore = autorecon.service_scan_semaphore
    while True:
        # If service scan semaphore is locked,
        # see if we can use port scan semaphore.
        if semaphore.locked():
            # This will be true unless user sets max_scans == max_port_scans
            if semaphore != autorecon.port_scan_semaphore:

                port_scan_task_count = 0
                for target in autorecon.scanning_targets:
                    for process_list in target.running_tasks.values():
                        if issubclass(process_list['plugin'].__class__, PortScanPlugin):
                            port_scan_task_count += 1
                # If no more targets, and we have room,
                # use port scan semaphore.
                if not autorecon.pending_targets and (config['max_port_scans'] - port_scan_task_count) >= 1:
                    if autorecon.port_scan_semaphore.locked():
                        await asyncio.sleep(1)
                        continue
                    semaphore = autorecon.port_scan_semaphore
                    break
                else:  # Do some math to see if we can use the port scan semaphore.
                    if (config['max_port_scans'] - (port_scan_task_count + (
                            len(autorecon.pending_targets) * config['port_scan_plugin_count']))) >= 1:
                        if autorecon.port_scan_semaphore.locked():
                            await asyncio.sleep(1)
                            continue
                        semaphore = autorecon.port_scan_semaphore
                        break
                    else:
                        await asyncio.sleep(1)
            else:
                break
        else:
            break
    return semaphore


async def port_scan(plugin, target):
    if config['ports']:
        if config['ports']['tcp'] or config['ports']['udp']:
            target.ports = {'tcp': None, 'udp': None}
            if config['ports']['tcp']:
                target.ports['tcp'] = ','.join(config['ports']['tcp'])
            if config['ports']['udp']:
                target.ports['udp'] = ','.join(config['ports']['udp'])
            if plugin.specific_ports is False:
                logger.warn(
                    'Port scan {bblue}' + plugin.name + ' {green}(' + plugin.slug +
                    '){rst} cannot be used to scan specific ports, and --ports was used. Skipping.',
                    verbosity=2)
                return {'type': 'port', 'plugin': plugin, 'result': []}
            else:
                if plugin.type == 'tcp' and not config['ports']['tcp']:
                    logger.warn(
                        'Port scan {bblue}' + plugin.name + ' {green}(' + plugin.slug +
                        '){rst} is a TCP port scan but no TCP ports were set using --ports. Skipping',
                        verbosity=2)
                    return {'type': 'port', 'plugin': plugin, 'result': []}
                elif plugin.type == 'udp' and not config['ports']['udp']:
                    logger.warn(
                        'Port scan {bblue}' + plugin.name + ' {green}(' + plugin.slug +
                        '){rst} is a UDP port scan but no UDP ports were set using --ports. Skipping',
                        verbosity=2)
                    return {'type': 'port', 'plugin': plugin, 'result': []}

    async with target.autorecon.port_scan_semaphore:
        logger.info(
            'Port scan {bblue}' + plugin.name + ' {green}(' + plugin.slug + '){rst} running against {byellow}' +
            target.address + '{rst}',
            verbosity=1)

        start_time = time.time()

        async with target.lock:
            target.running_tasks[plugin.slug] = {'plugin': plugin, 'processes': [], 'start': start_time}

        try:
            result = await plugin.run(target)
        except Exception as ex:
            exc_type, exc_value, exc_tb = sys.exc_info()
            error_text = ''.join(traceback.format_exception(exc_type, exc_value, exc_tb)[-2:])
            raise Exception(logger.cprint(
                'Error: Port scan {bblue}' + plugin.name + ' {green}(' + plugin.slug +
                '){rst} running against {byellow}' + target.address + '{rst} produced an exception:\n\n' + error_text,
                color=Fore.RED, char='!', printmsg=False))

        for process_dict in target.running_tasks[plugin.slug]['processes']:
            if process_dict['process'].returncode is None:
                logger.warn(
                    'A process was left running after port scan {bblue}' + plugin.name + ' {green}(' + plugin.slug +
                    '){rst} against {byellow}' + target.address + '{rst} finished. Please ensure non-blocking '
                                                                  'processes are awaited before the run coroutine '
                                                                  'finishes. Awaiting now.',
                    verbosity=2)
                await process_dict['process'].wait()

            if process_dict['process'].returncode != 0:
                errors = []
                while True:
                    line = await process_dict['stderr'].readline()
                    if line is not None:
                        errors.append(line + '\n')
                    else:
                        break
                logger.error(
                    'Port scan {bblue}' + plugin.name + ' {green}(' + plugin.slug +
                    '){rst} ran a command against {byellow}' + target.address +
                    '{rst} which returned a non-zero exit code (' + str(
                        process_dict[
                            'process'].returncode) + '). Check ' + target.scandir + '/_errors.log for more details.',
                    verbosity=2)
                async with target.lock:
                    with open(os.path.join(target.scandir, '_errors.log'), 'a') as file:
                        file.writelines(
                            '[*] Port scan ' + plugin.name + ' (' + plugin.slug +
                            ') ran a command which returned a non-zero exit code (' + str(
                                process_dict['process'].returncode) + ').\n')
                        file.writelines('[-] Command: ' + process_dict['cmd'] + '\n')
                        if errors:
                            file.writelines(['[-] Error Output:\n'] + errors + ['\n'])
                        else:
                            file.writelines('\n')

        elapsed_time = task_utils.calculate_elapsed_time(start_time)

        async with target.lock:
            target.running_tasks.pop(plugin.slug, None)

        logger.info(
            'Port scan {bblue}' + plugin.name + ' {green}(' + plugin.slug + '){rst} against {byellow}' +
            target.address + '{rst} finished in ' + elapsed_time,
            verbosity=2)
        return {'type': 'port', 'plugin': plugin, 'result': result}


async def service_scan(plugin, service):
    semaphore = service.target.autorecon.service_scan_semaphore

    if not config['force_services']:
        semaphore = await get_semaphore(service.target.autorecon)

    plugin_pending = True

    while plugin_pending:
        global_plugin_count = 0
        target_plugin_count = 0

        if plugin.max_global_instances and plugin.max_global_instances > 0:
            async with service.target.autorecon.lock:
                # Count currently running plugin instances.
                for target in service.target.autorecon.scanning_targets:
                    for task in target.running_tasks.values():
                        if plugin == task['plugin']:
                            global_plugin_count += 1
                            if global_plugin_count >= plugin.max_global_instances:
                                break
                    if global_plugin_count >= plugin.max_global_instances:
                        break
            if global_plugin_count >= plugin.max_global_instances:
                await asyncio.sleep(1)
                continue

        if plugin.max_target_instances and plugin.max_target_instances > 0:
            async with service.target.lock:
                # Count currently running plugin instances.
                for task in service.target.running_tasks.values():
                    if plugin == task['plugin']:
                        target_plugin_count += 1
                        if target_plugin_count >= plugin.max_target_instances:
                            break
            if target_plugin_count >= plugin.max_target_instances:
                await asyncio.sleep(1)
                continue

        # If we get here, we can run the plugin.
        plugin_pending = False

        async with semaphore:
            # Create variables for fformat references.
            address = service.target.address
            addressv6 = service.target.address
            ipaddress = service.target.ip
            ipaddressv6 = service.target.ip
            scandir = service.target.scandir
            protocol = service.protocol
            port = service.port
            name = service.name

            if not config['no_port_dirs']:
                scandir = os.path.join(scandir, protocol + str(port))
                os.makedirs(scandir, exist_ok=True)
                os.makedirs(os.path.join(scandir, 'xml'), exist_ok=True)

            # Special cases for HTTP.
            http_scheme = 'https' if 'https' in service.name or service.secure is True else 'http'

            nmap_extra = service.target.autorecon.args.nmap
            if service.target.autorecon.args.nmap_append:
                nmap_extra += ' ' + service.target.autorecon.args.nmap_append

            if protocol == 'udp':
                nmap_extra += ' -sU'

            if service.target.ipversion == 'IPv6':
                nmap_extra += ' -6'
                if addressv6 == service.target.ip:
                    addressv6 = '[' + addressv6 + ']'
                ipaddressv6 = '[' + ipaddressv6 + ']'

            tag = service.tag + '/' + plugin.slug

            logger.info(
                'Service scan {bblue}' + plugin.name + ' {green}(' + tag + '){rst} running against {byellow}' +
                service.target.address + '{rst}',
                verbosity=1)

            start_time = time.time()

            async with service.target.lock:
                service.target.running_tasks[tag] = {'plugin': plugin, 'processes': [], 'start': start_time}

            try:
                result = await plugin.run(service)
            except Exception as ex:
                exc_type, exc_value, exc_tb = sys.exc_info()
                error_text = ''.join(traceback.format_exception(exc_type, exc_value, exc_tb)[-2:])
                raise Exception(logger.cprint(
                    'Error: Service scan {bblue}' + plugin.name + ' {green}(' + tag + '){rst} running against {byellow}'
                    + service.target.address + '{rst} produced an exception:\n\n' + error_text,
                    color=Fore.RED, char='!', printmsg=False))

            for process_dict in service.target.running_tasks[tag]['processes']:
                if process_dict['process'].returncode is None:
                    logger.warn(
                        'A process was left running after service scan {bblue}' + plugin.name + ' {green}(' + tag +
                        '){rst} against {byellow}' + service.target.address +
                        '{rst} finished. Please ensure non-blocking processes are awaited before the run '
                        'coroutine finishes. Awaiting now.',
                        verbosity=2)
                    await process_dict['process'].wait()

                if process_dict['process'].returncode != 0 and not (
                        process_dict['cmd'].startswith('curl') and process_dict['process'].returncode == 22):
                    errors = []
                    while True:
                        line = await process_dict['stderr'].readline()
                        if line is not None:
                            errors.append(line + '\n')
                        else:
                            break
                    logger.error(
                        'Service scan {bblue}' + plugin.name + ' {green}(' + tag +
                        '){rst} ran a command against {byellow}' + service.target.address +
                        '{rst} which returned a non-zero exit code (' + str(
                            process_dict[
                                'process'].returncode) + '). Check ' + service.target.scandir +
                        '/_errors.log for more details.',
                        verbosity=2)
                    async with service.target.lock:
                        with open(os.path.join(service.target.scandir, '_errors.log'), 'a') as file:
                            file.writelines(
                                '[*] Service scan ' + plugin.name + ' (' + tag +
                                ') ran a command which returned a non-zero exit code (' + str(
                                    process_dict['process'].returncode) + ').\n')
                            file.writelines('[-] Command: ' + process_dict['cmd'] + '\n')
                            if errors:
                                file.writelines(['[-] Error Output:\n'] + errors + ['\n'])
                            else:
                                file.writelines('\n')

            elapsed_time = task_utils.calculate_elapsed_time(start_time)

            async with service.target.lock:
                service.target.running_tasks.pop(tag, None)

            logger.info(
                'Service scan {bblue}' + plugin.name + ' {green}(' + tag + '){rst} against {byellow}' +
                service.target.address + '{rst} finished in ' + elapsed_time,
                verbosity=2)
            return {'type': 'service', 'plugin': plugin, 'result': result}


async def generate_report(plugin, targets):
    semaphore = autorecon.service_scan_semaphore

    if not config['force_services']:
        semaphore = await get_semaphore(autorecon)

    async with semaphore:
        try:
            result = await plugin.run(targets)
        except Exception as ex:
            exc_type, exc_value, exc_tb = sys.exc_info()
            error_text = ''.join(traceback.format_exception(exc_type, exc_value, exc_tb)[-2:])
            raise Exception(logger.cprint(
                'Error: Report plugin {bblue}' + plugin.name + ' {green}(' + plugin.slug +
                '){rst} produced an exception:\n\n' + error_text,
                color=Fore.RED, char='!', printmsg=False))


async def scan_target(target):
    os.makedirs(os.path.abspath(config['output']), exist_ok=True)

    if config['single_target']:
        basedir = os.path.abspath(config['output'])
    else:
        basedir = os.path.abspath(os.path.join(config['output'], target.address))
        os.makedirs(basedir, exist_ok=True)

    target.basedir = basedir

    scandir = os.path.join(basedir, 'scans')
    target.scandir = scandir
    os.makedirs(scandir, exist_ok=True)

    os.makedirs(os.path.join(scandir, 'xml'), exist_ok=True)

    if not config['only_scans_dir']:
        exploitdir = os.path.join(basedir, 'exploit')
        os.makedirs(exploitdir, exist_ok=True)

        lootdir = os.path.join(basedir, 'loot')
        os.makedirs(lootdir, exist_ok=True)

        reportdir = os.path.join(basedir, 'report')
        os.makedirs(reportdir, exist_ok=True)

        screenshotdir = os.path.join(reportdir, 'screenshots')
        os.makedirs(screenshotdir, exist_ok=True)
    else:
        reportdir = scandir

    target.reportdir = reportdir

    pending = []

    heartbeat = asyncio.create_task(tasks.start_heartbeat(target, period=config['heartbeat']))

    services = []
    if config['force_services']:
        forced_services = [x.strip().lower() for x in config['force_services']]

        for forced_service in forced_services:
            match = re.search(
                r'(?P<protocol>(tcp|udp))\/(?P<port>\d+)\/(?P<service>[\w\-]+)(\/(?P<secure>secure|insecure))?',
                forced_service)
            if match:
                protocol = match.group('protocol')
                if config.get('proxychains') and protocol == 'udp':
                    logger.error('The service ' + forced_service + ' uses UDP and --proxychains is enabled. Skipping.',
                          verbosity=2)
                    continue
                port = int(match.group('port'))
                service = match.group('service')
                secure = True if match.group('secure') == 'secure' else False
                service = assets.Service(protocol, port, service, secure)
                service.target = target
                services.append(service)

        if services:
            pending.append(asyncio.create_task(asyncio.sleep(0)))
        else:
            logger.error(
                'No services were defined. Please check your service syntax: [tcp|udp]/<port>/<service-name>/'
                '[secure|insecure]')
            heartbeat.cancel()
            autorecon.errors = True
            return
    else:
        for plugin in target.autorecon.plugin_types['port']:

            if config['port_scans'] and plugin.slug in config['port_scans']:
                matching_tags = True
                excluded_tags = False
            else:
                plugin_tag_set = set(plugin.tags)

                matching_tags = False
                for tag_group in target.autorecon.tags:
                    if set(tag_group).issubset(plugin_tag_set):
                        matching_tags = True
                        break

                excluded_tags = False
                for tag_group in target.autorecon.excluded_tags:
                    if set(tag_group).issubset(plugin_tag_set):
                        excluded_tags = True
                        break

            if matching_tags and not excluded_tags:
                target.scans['ports'][plugin.slug] = {'plugin': plugin, 'commands': []}
                pending.append(asyncio.create_task(port_scan(plugin, target)))

    async with autorecon.lock:
        autorecon.scanning_targets.append(target)

    start_time = time.time()
    logger.info('Scanning target {byellow}' + target.address + '{rst}')

    timed_out = False
    while pending:
        done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED, timeout=1)

        # Check if global timeout has occurred.
        if config['target_timeout'] is not None:
            elapsed_seconds = round(time.time() - start_time)
            m, s = divmod(elapsed_seconds, 60)
            if m >= config['target_timeout']:
                timed_out = True
                break

        if not config['force_services']:
            # Extract Services
            services = []

            async with target.lock:
                while target.pending_services:
                    services.append(target.pending_services.pop(0))

            for task in done:
                try:
                    if task.exception():
                        print(task.exception())
                        continue
                except asyncio.InvalidStateError:
                    pass

                if task.result()['type'] == 'port':
                    for service in (task.result()['result'] or []):
                        services.append(service)

        for service in services:
            if service.full_tag not in target.services:
                target.services.append(service.full_tag)
            else:
                continue

            logger.info('Identified service {bmagenta}' + service.name + '{rst} on {bmagenta}' + service.protocol + '/'
                        + str(service.port) + '{rst} on {byellow}' + target.address + '{rst}', verbosity=1)

            if not config['only_scans_dir']:
                with open(os.path.join(target.reportdir, 'notes.txt'), 'a') as file:
                    file.writelines(
                        '[*] ' + service.name + ' found on ' + service.protocol + '/' + str(service.port) + '.\n\n\n\n')

            service.target = target

            # Create variables for command references.
            address = target.address
            addressv6 = target.address
            ipaddress = target.ip
            ipaddressv6 = target.ip
            scandir = target.scandir
            protocol = service.protocol
            port = service.port

            if not config['no_port_dirs']:
                scandir = os.path.join(scandir, protocol + str(port))
                os.makedirs(scandir, exist_ok=True)
                os.makedirs(os.path.join(scandir, 'xml'), exist_ok=True)

            # Special cases for HTTP.
            http_scheme = 'https' if 'https' in service.name or service.secure is True else 'http'

            nmap_extra = target.autorecon.args.nmap
            if target.autorecon.args.nmap_append:
                nmap_extra += ' ' + target.autorecon.args.nmap_append

            if protocol == 'udp':
                nmap_extra += ' -sU'

            if target.ipversion == 'IPv6':
                nmap_extra += ' -6'
                if addressv6 == target.ip:
                    addressv6 = '[' + addressv6 + ']'
                ipaddressv6 = '[' + ipaddressv6 + ']'

            service_match = False
            matching_plugins = []
            heading = False

            for plugin in target.autorecon.plugin_types['service']:
                plugin_was_run = False
                plugin_service_match = False
                plugin_tag = service.tag + '/' + plugin.slug

                for service_dict in plugin.services:
                    if service_dict['protocol'] == protocol and port in service_dict['port']:
                        for name in service_dict['name']:
                            if service_dict['negative_match']:
                                if name not in plugin.ignore_service_names:
                                    plugin.ignore_service_names.append(name)
                            else:
                                if name not in plugin.service_names:
                                    plugin.service_names.append(name)
                    else:
                        continue

                for s in plugin.service_names:
                    if re.search(s, service.name):
                        plugin_service_match = True

                    if plugin_service_match:
                        if config['service_scans'] and plugin.slug in config['service_scans']:
                            matching_tags = True
                            excluded_tags = False
                        else:
                            plugin_tag_set = set(plugin.tags)

                            matching_tags = False
                            for tag_group in target.autorecon.tags:
                                if set(tag_group).issubset(plugin_tag_set):
                                    matching_tags = True
                                    break

                            excluded_tags = False
                            for tag_group in target.autorecon.excluded_tags:
                                if set(tag_group).issubset(plugin_tag_set):
                                    excluded_tags = True
                                    break

                        # TODO: Maybe make this less messy, keep manual-only plugins separate?
                        plugin_is_runnable = False
                        for member_name, _ in inspect.getmembers(plugin, predicate=inspect.ismethod):
                            if member_name == 'run':
                                plugin_is_runnable = True
                                break

                        if plugin_is_runnable and matching_tags and not excluded_tags:
                            # Skip plugin if run_once_boolean and plugin already in target scans
                            if plugin.run_once_boolean:
                                plugin_queued = False
                                for s in target.scans['services']:
                                    if plugin.slug in target.scans['services'][s]:
                                        plugin_queued = True
                                        logger.warn(
                                            '{byellow}[' + plugin_tag + ' against ' + target.address +
                                            ']{srst} Plugin should only be run once and it appears to have '
                                            'already been queued. Skipping.{rst}',
                                            verbosity=2)
                                        break
                                if plugin_queued:
                                    break

                            # Skip plugin if require_ssl_boolean and port is not secure
                            if plugin.require_ssl_boolean and not service.secure:
                                plugin_service_match = False
                                break

                            # Skip plugin if service port is in ignore_ports:
                            if port in plugin.ignore_ports[protocol]:
                                plugin_service_match = False
                                logger.warn(
                                    '{byellow}[' + plugin_tag + ' against ' + target.address +
                                    ']{srst} Plugin cannot be run against ' + protocol + ' port ' + str(
                                        port) + '. Skipping.{rst}', verbosity=2)
                                break

                            # Skip plugin if plugin has required ports and service port is not in them:
                            if plugin.ports[protocol] and port not in plugin.ports[protocol]:
                                plugin_service_match = False
                                logger.warn(
                                    '{byellow}[' + plugin_tag + ' against ' + target.address +
                                    ']{srst} Plugin can only run on specific ports. Skipping.{rst}',
                                    verbosity=2)
                                break

                            for i in plugin.ignore_service_names:
                                if re.search(i, service.name):
                                    logger.warn(
                                        '{byellow}[' + plugin_tag + ' against ' + target.address +
                                        ']{srst} Plugin cannot be run against this service. Skipping.{rst}',
                                        verbosity=2)
                                    break

                            # TODO: check if plugin matches tags, BUT run manual commands anyway!
                            plugin_was_run = True
                            matching_plugins.append(plugin)

                        for member_name, _ in inspect.getmembers(plugin, predicate=inspect.ismethod):
                            if member_name == 'manual':
                                try:
                                    plugin.manual(service, plugin_was_run)
                                except Exception as ex:
                                    exc_type, exc_value, exc_tb = sys.exc_info()
                                    error_text = ''.join(traceback.format_exception(exc_type, exc_value, exc_tb)[-2:])
                                    logger.cprint(
                                        'Error: Service scan {bblue}' + plugin.name + ' {green}(' + plugin_tag +
                                        '){rst} running against {byellow}' + target.address +
                                        '{rst} produced an exception when generating manual commands:\n\n' + error_text,
                                        color=Fore.RED, char='!', printmsg=True)

                                if service.manual_commands:
                                    plugin_run = False
                                    for s in target.scans['services']:
                                        if plugin.slug in target.scans['services'][s]:
                                            plugin_run = True
                                            break
                                    if not plugin.run_once_boolean or (plugin.run_once_boolean and not plugin_run):
                                        with open(os.path.join(target.scandir, '_manual_commands.txt'), 'a') as file:
                                            if not heading:
                                                file.write(
                                                    e('[*] {service.name} on {service.protocol}/{service.port}\n\n'))
                                                heading = True
                                            for description, commands in service.manual_commands.items():
                                                try:
                                                    file.write('\t[-] ' + e(description) + '\n\n')
                                                    for command in commands:
                                                        file.write('\t\t' + e(command) + '\n\n')
                                                except Exception as ex:
                                                    exc_type, exc_value, exc_tb = sys.exc_info()
                                                    error_text = ''.join(
                                                        traceback.format_exception(exc_type, exc_value, exc_tb)[-2:])
                                                    logger.cprint(
                                                        'Error: Service scan {bblue}' + plugin.name + ' {green}(' +
                                                        plugin_tag + '){rst} running against {byellow}' +
                                                        target.address + '{rst} produced an exception when evaluating'
                                                                         ' manual commands:\n\n' + error_text,
                                                        color=Fore.RED, char='!', printmsg=True)
                                            file.flush()

                                service.manual_commands = {}
                                break

                        break

                if plugin_service_match:
                    service_match = True

            for plugin in matching_plugins:
                plugin_tag = service.tag + '/' + plugin.slug

                if plugin.run_once_boolean:
                    plugin_tag = plugin.slug

                plugin_queued = False
                if service in target.scans['services']:
                    for s in target.scans['services']:
                        if plugin_tag in target.scans['services'][s]:
                            plugin_queued = True
                            logger.warn(
                                '{byellow}[' + plugin_tag + ' against ' + target.address +
                                ']{srst} Plugin appears to have already been queued, but it is not marked as run_once. '
                                'Possible duplicate service tag? Skipping.{rst}',
                                verbosity=2)
                            break

                if plugin_queued:
                    continue
                else:
                    if service not in target.scans['services']:
                        target.scans['services'][service] = {}
                    target.scans['services'][service][plugin_tag] = {'plugin': plugin, 'commands': []}

                pending.add(asyncio.create_task(service_scan(plugin, service)))

            if not service_match:
                logger.warn(
                    '{byellow}[' + target.address + ']{srst} Service ' + service.full_tag() +
                    ' did not match any plugins based on the service name.{rst}',
                    verbosity=2)
                if service.name not in ['status', 'tcpwrapped',
                                        'unknown'] and service.full_tag() not in target.autorecon.missing_services:
                    target.autorecon.missing_services.append(service.full_tag())
    for plugin in target.autorecon.plugin_types['report']:
        if config['reports'] and plugin.slug in config['reports']:
            matching_tags = True
            excluded_tags = False
        else:
            plugin_tag_set = set(plugin.tags)

            matching_tags = False
            for tag_group in target.autorecon.tags:
                if set(tag_group).issubset(plugin_tag_set):
                    matching_tags = True
                    break

            excluded_tags = False
            for tag_group in target.autorecon.excluded_tags:
                if set(tag_group).issubset(plugin_tag_set):
                    excluded_tags = True
                    break

        if matching_tags and not excluded_tags:
            pending.add(asyncio.create_task(generate_report(plugin, [target])))

    while pending:
        done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED, timeout=1)

    heartbeat.cancel()
    elapsed_time = task_utils.calculate_elapsed_time(start_time)

    if timed_out:

        for task in pending:
            task.cancel()

        for process_list in target.running_tasks.values():
            for process_dict in process_list['processes']:
                try:
                    process_dict['process'].kill()
                except ProcessLookupError:
                    pass

        logger.warn('{byellow}Scanning target ' + target.address + ' took longer than the specified target period (' +
                    str(config['target_timeout']) + ' min). Cancelling scans and moving to next target.{rst}')
    else:
        logger.info('Finished scanning target {byellow}' + target.address + '{rst} in ' + elapsed_time)

    async with autorecon.lock:
        autorecon.completed_targets.append(target)
        autorecon.scanning_targets.remove(target)


async def run():
    # Find config file.
    if os.path.isfile(os.path.join(os.getcwd(), 'config.yaml')):
        config_file = os.path.join(os.getcwd(), 'config.yaml')
    elif os.path.isfile(os.path.join(config['config_dir'], 'config.yaml')):
        config_file = os.path.join(config['config_dir'], 'config.yaml')
    else:
        config_file = None

    config["plugins_dir"] = None
    config["global_file"] = None

    parser = argparse.ArgumentParser(add_help=False,
                                     description='Network reconnaissance tool to port scan and automatically '
                                                 'enumerate services found on multiple targets.')
    parser.add_argument('targets', action='store',
                        help='IP addresses (e.g. 10.0.0.1), CIDR notation (e.g. 10.0.0.1/24), '
                             'or resolvable hostnames (e.g. foo.bar) to scan.',
                        nargs='*')
    parser.add_argument('-t', '--target-file', action='store', type=str, default='', help='Read targets from file.')
    parser.add_argument('-p', '--ports', action='store', type=str,
                        help='Comma separated list of ports / port ranges to scan. Specify TCP/UDP ports by '
                             'prepending list with T:/U: To scan both TCP/UDP, put port(s) at start or specify '
                             'B: e.g. 53,T:21-25,80,U:123,B:123. Default: %(default)s')
    parser.add_argument('-m', '--max-scans', action='store', type=int,
                        help='The maximum number of concurrent scans to run. Default: %(default)s')
    parser.add_argument('-mp', '--max-port-scans', action='store', type=int,
                        help='The maximum number of concurrent port scans to run. Default: 10 (approx 20%% of max-scans'
                             ' unless specified)')
    parser.add_argument('-c', '--config', action='store', type=str, default=config_file, dest='config_file',
                        help='Location of AutoRecon\'s config file. Default: %(default)s')
    parser.add_argument('-g', '--global-file', action='store', type=str,
                        help='Location of AutoRecon\'s global file. Default: %(default)s')
    parser.add_argument('--tags', action='store', type=str, default='default',
                        help='Tags to determine which plugins should be included. Separate tags by a plus symbol (+) '
                             'to group tags together. Separate groups with a comma (,) to create multiple groups.'
                             ' For a plugin to be included, it must have all the tags specified in at least one group.'
                             ' Default: %(default)s')
    parser.add_argument('--exclude-tags', action='store', type=str, default='', metavar='TAGS',
                        help='Tags to determine which plugins should be excluded. Separate tags by a plus symbol (+) '
                             'to group tags together. Separate groups with a comma (,) to create multiple groups. '
                             'For a plugin to be excluded, it must have all the tags specified in at least one group.'
                             ' Default: %(default)s')
    parser.add_argument('--port-scans', action='store', type=str, metavar='PLUGINS',
                        help='Override --tags / --exclude-tags for the listed PortScan plugins (comma separated).'
                             ' Default: %(default)s')
    parser.add_argument('--service-scans', action='store', type=str, metavar='PLUGINS',
                        help='Override --tags / --exclude-tags for the listed ServiceScan plugins (comma separated).'
                             ' Default: %(default)s')
    parser.add_argument('--reports', action='store', type=str, metavar='PLUGINS',
                        help='Override --tags / --exclude-tags for the listed Report plugins (comma separated). '
                             'Default: %(default)s')
    parser.add_argument('-l', '--list', action='store', nargs='?', const='plugins', metavar='TYPE',
                        help='List all plugins or plugins of a specific type. e.g. --list, --list port, --list service')
    parser.add_argument('-o', '--output', action='store', help='The output directory for results. Default: %(default)s')
    parser.add_argument('--single-target', action='store_true',
                        help='Only scan a single target. A directory named after the target will not be created. '
                             'Instead, the directory structure will be created within the output directory. '
                             'Default: %(default)s')
    parser.add_argument('--only-scans-dir', action='store_true',
                        help='Only create the "scans" directory for results. Other directories (e.g. exploit, '
                             'loot, report) will not be created. Default: %(default)s')
    parser.add_argument('--no-port-dirs', action='store_true',
                        help='Don\'t create directories for ports (e.g. scans/tcp80, scans/udp53). '
                             'Instead store all results in the "scans" directory itself. Default: %(default)s')
    parser.add_argument('--heartbeat', action='store', type=int,
                        help='Specifies the heartbeat interval (in seconds) for scan status messages. '
                             'Default: %(default)s')
    parser.add_argument('--timeout', action='store', type=int,
                        help='Specifies the maximum amount of time in minutes that AutoRecon should run for. '
                             'Default: %(default)s')
    parser.add_argument('--target-timeout', action='store', type=int,
                        help='Specifies the maximum amount of time in minutes that a target should be scanned for '
                             'before abandoning it and moving on. Default: %(default)s')
    nmap_group = parser.add_mutually_exclusive_group()
    nmap_group.add_argument('--nmap', action='store',
                            help='Override the {nmap_extra} variable in scans. Default: %(default)s')
    nmap_group.add_argument('--nmap-append', action='store',
                            help='Append to the default {nmap_extra} variable in scans. Default: %(default)s')
    parser.add_argument('--disable-sanity-checks', action='store_true',
                        help='Disable sanity checks that would otherwise prevent the scans from running. Default: '
                             '%(default)s')
    parser.add_argument('--disable-keyboard-control', action='store_true',
                        help='Disables keyboard control ([s]tatus, Up, Down) if you are in SSH or Docker.')
    parser.add_argument('--force-services', action='store', nargs='+', metavar='SERVICE',
                        help='A space separated list of services in the following style: tcp/80/http tcp/443/https/'
                             'secure')
    parser.add_argument('-mpti', '--max-plugin-target-instances', action='store', nargs='+', metavar='PLUGIN:NUMBER',
                        help='A space separated list of plugin slugs with the max number of instances (per target) '
                             'in the following style: nmap-http:2 dirbuster:1. Default: %(default)s')
    parser.add_argument('-mpgi', '--max-plugin-global-instances', action='store', nargs='+', metavar='PLUGIN:NUMBER',
                        help='A space separated list of plugin slugs with the max number of global instances in the '
                             'following style: nmap-http:2 dirbuster:1. Default: %(default)s')
    parser.add_argument('--accessible', action='store_true',
                        help='Attempts to make AutoRecon output more accessible to screenreaders. Default: %(default)s')
    parser.add_argument('-v', '--verbose', action='count', help='Enable verbose output. Repeat for more verbosity.')
    parser.add_argument('--version', action='store_true', help='Prints the AutoRecon version and exits.')
    parser.error = lambda s: logger.fail(s[0].upper() + s[1:])
    args, unknown = parser.parse_known_args()

    errors = False

    autorecon.argparse = parser

    if args.version:
        print('Vulnman-Scanner v' + VERSION)
        sys.exit(0)

    def unknown_help():
        if '-h' in unknown:
            parser.print_help()
            print()

    # Parse config file and args for global.toml first.
    if not args.config_file:
        unknown_help()
        logger.fail('Error: Could not find config.toml in the current directory or ~/.config/AutoRecon.')

    if not os.path.isfile(args.config_file):
        unknown_help()
        logger.fail('Error: Specified config file "' + args.config_file + '" does not exist.')

    with open(args.config_file) as c:
        try:
            config_yaml = yaml.safe_load(c)
            for key, val in config_yaml.items():
                key = slugify(key)
                if key == 'global-file':
                    config['global_file'] = val
        except yaml.YAMLError:
            unknown_help()
            logger.fail('Error: Couldn\'t parse ' + args.config_file + ' config file. Check syntax.')

    args_dict = vars(args)
    for key in args_dict:
        key = slugify(key)
        if key == 'global-file' and args_dict['global_file'] is not None:
            config['global_file'] = args_dict['global_file']

    autorecon.load_plugins()

    if len(autorecon.plugin_types['port']) == 0:
        unknown_help()
    # fail('Error: There are no valid PortScan plugins in the plugins directory "' + config['plugins_dir'] + '".')

    # Sort plugins by priority.
    autorecon.plugin_types['port'].sort(key=lambda x: x.priority)
    autorecon.plugin_types['service'].sort(key=lambda x: x.priority)
    autorecon.plugin_types['report'].sort(key=lambda x: x.priority)

    other_options = []
    for key, val in config_yaml.items():
        if key == 'global' and isinstance(val, dict):  # Process global plugin options.
            for gkey, gval in config_toml['global'].items():
                if isinstance(gval, bool):
                    for action in autorecon.argparse._actions:
                        if action.dest == 'global.' + slugify(gkey).replace('-', '_'):
                            if action.const is True:
                                action.__setattr__('default', gval)
                            break
                else:
                    if autorecon.argparse.get_default('global.' + slugify(gkey).replace('-', '_')):
                        autorecon.argparse.set_defaults(**{'global.' + slugify(gkey).replace('-', '_'): gval})
        elif isinstance(val, dict):  # Process potential plugin arguments.
            for pkey, pval in config_yaml[key].items():
                if autorecon.argparse.get_default(
                        slugify(key).replace('-', '_') + '.' + slugify(pkey).replace('-', '_')):
                    autorecon.argparse.set_defaults(
                        **{slugify(key).replace('-', '_') + '.' + slugify(pkey).replace('-', '_'): pval})
        else:  # Process potential other options.
            key = key.replace('-', '_')
            if key in configurable_keys:
                other_options.append(key)
                config[key] = val
                autorecon.argparse.set_defaults(**{key: val})

    for key, val in config.items():
        if key not in other_options:
            autorecon.argparse.set_defaults(**{key: val})

    parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS,
                        help='Show this help message and exit.')
    args = parser.parse_args()

    args_dict = vars(args)
    for key in args_dict:
        if key in configurable_keys and args_dict[key] is not None:
            # Special case for booleans
            if key in configurable_boolean_keys and config[key]:
                continue
            config[key] = args_dict[key]
    autorecon.args = args

    if args.list:
        type = args.list.lower()
        if type in ['plugin', 'plugins', 'port', 'ports', 'portscan', 'portscans']:
            for p in autorecon.plugin_types['port']:
                print('PortScan: ' + p.name + ' (' + p.slug + ')' + (' - ' + p.description if p.description else ''))
        if type in ['plugin', 'plugins', 'service', 'services', 'servicescan', 'servicescans']:
            for p in autorecon.plugin_types['service']:
                print('ServiceScan: ' + p.name + ' (' + p.slug + ')' + (' - ' + p.description if p.description else ''))
        if type in ['plugin', 'plugins', 'report', 'reports', 'reporting']:
            for p in autorecon.plugin_types['report']:
                print('Report: ' + p.name + ' (' + p.slug + ')' + (' - ' + p.description if p.description else ''))

        sys.exit(0)

    max_plugin_target_instances = {}
    if config['max_plugin_target_instances']:
        for plugin_instance in config['max_plugin_target_instances']:
            plugin_instance = plugin_instance.split(':', 1)
            if len(plugin_instance) == 2:
                if plugin_instance[0] not in autorecon.plugins:
                    logger.error('Invalid plugin slug (' + plugin_instance[0] + ':' + plugin_instance[
                        1] + ') provided to --max-plugin-target-instances.')
                    errors = True
                elif not plugin_instance[1].isdigit() or int(plugin_instance[1]) == 0:
                    logger.error('Invalid number of instances (' + plugin_instance[0] + ':' + plugin_instance[
                        1] + ') provided to --max-plugin-target-instances. Must be a non-zero positive integer.')
                    errors = True
                else:
                    max_plugin_target_instances[plugin_instance[0]] = int(plugin_instance[1])
            else:
                logger.error(
                    'Invalid value provided to --max-plugin-target-instances. Values must be in the format '
                    'PLUGIN:NUMBER.')

    max_plugin_global_instances = {}
    if config['max_plugin_global_instances']:
        for plugin_instance in config['max_plugin_global_instances']:
            plugin_instance = plugin_instance.split(':', 1)
            if len(plugin_instance) == 2:
                if plugin_instance[0] not in autorecon.plugins:
                    logger.error('Invalid plugin slug (' + plugin_instance[0] + ':' + plugin_instance[
                        1] + ') provided to --max-plugin-global-instances.')
                    errors = True
                elif not plugin_instance[1].isdigit() or int(plugin_instance[1]) == 0:
                    logger.error('Invalid number of instances (' + plugin_instance[0] + ':' + plugin_instance[
                        1] + ') provided to --max-plugin-global-instances. Must be a non-zero positive integer.')
                    errors = True
                else:
                    max_plugin_global_instances[plugin_instance[0]] = int(plugin_instance[1])
            else:
                logger.error(
                    'Invalid value provided to --max-plugin-global-instances. Values must be in the format '
                    'PLUGIN:NUMBER.')

    for plugin in autorecon.plugins.values():
        if hasattr(plugin, 'max_target_instances') and plugin.slug in max_plugin_target_instances:
            plugin.max_target_instances = max_plugin_target_instances[plugin.slug]

        if hasattr(plugin, 'max_global_instances') and plugin.slug in max_plugin_global_instances:
            plugin.max_global_instances = max_plugin_global_instances[plugin.slug]

        for member_name, _ in inspect.getmembers(plugin, predicate=inspect.ismethod):
            if member_name == 'check':
                plugin.check()
                continue

    if config['ports']:
        ports_to_scan = {'tcp': [], 'udp': []}
        unique = {'tcp': [], 'udp': []}

        ports = config['ports'].split(',')
        mode = 'both'
        for port in ports:
            port = port.strip()
            if port == '':
                continue

            if port.startswith('B:'):
                mode = 'both'
                port = port.split('B:')[1]
            elif port.startswith('T:'):
                mode = 'tcp'
                port = port.split('T:')[1]
            elif port.startswith('U:'):
                mode = 'udp'
                port = port.split('U:')[1]

            match = re.search(r'^([0-9]+)\-([0-9]+)$', port)
            if match:
                num1 = int(match.group(1))
                num2 = int(match.group(2))

                if num1 > 65535:
                    logger.fail('Error: A provided port number was too high: ' + str(num1))

                if num2 > 65535:
                    logger.fail('Error: A provided port number was too high: ' + str(num2))

                if num1 == num2:
                    port_range = [num1]

                if num2 > num1:
                    port_range = list(range(num1, num2 + 1, 1))
                else:
                    port_range = list(range(num2, num1 + 1, 1))
                    num1 = num1 + num2
                    num2 = num1 - num2
                    num1 = num1 - num2

                if mode == 'tcp' or mode == 'both':
                    for num in port_range:
                        if num in ports_to_scan['tcp']:
                            ports_to_scan['tcp'].remove(num)
                    ports_to_scan['tcp'].append(str(num1) + '-' + str(num2))
                    unique['tcp'] = list(set(unique['tcp'] + port_range))

                if mode == 'udp' or mode == 'both':
                    for num in port_range:
                        if num in ports_to_scan['udp']:
                            ports_to_scan['udp'].remove(num)
                    ports_to_scan['udp'].append(str(num1) + '-' + str(num2))
                    unique['udp'] = list(set(unique['tcp'] + port_range))
            else:
                match = re.search('^[0-9]+$', port)
                if match:
                    num = int(port)

                    if num > 65535:
                        logger.fail('Error: A provided port number was too high: ' + str(num))

                    if mode == 'tcp' or mode == 'both':
                        ports_to_scan['tcp'].append(str(num)) if num not in unique['tcp'] else ports_to_scan['tcp']
                        unique['tcp'].append(num)

                    if mode == 'udp' or mode == 'both':
                        ports_to_scan['udp'].append(str(num)) if num not in unique['udp'] else ports_to_scan['udp']
                        unique['udp'].append(num)
                else:
                    logger.fail('Error: Invalid port number: ' + str(port))
        config['ports'] = ports_to_scan

    if config['max_scans'] <= 0:
        logger.error('Argument -m/--max-scans must be at least 1.')
        errors = True

    if config['max_port_scans'] is None:
        config['max_port_scans'] = max(1, round(config['max_scans'] * 0.2))
    else:
        if config['max_port_scans'] <= 0:
            logger.error('Argument -mp/--max-port-scans must be at least 1.')
            errors = True

        if config['max_port_scans'] > config['max_scans']:
            logger.error('Argument -mp/--max-port-scans cannot be greater than argument -m/--max-scans.')
            errors = True

    if config['heartbeat'] <= 0:
        logger.error('Argument --heartbeat must be at least 1.')
        errors = True

    if config['timeout'] is not None and config['timeout'] <= 0:
        logger.error('Argument --timeout must be at least 1.')
        errors = True

    if config['target_timeout'] is not None and config['target_timeout'] <= 0:
        logger.error('Argument --target-timeout must be at least 1.')
        errors = True

    if config['timeout'] is not None and config['target_timeout'] is not None and config['timeout'] < config[
        'target_timeout']:
        logger.error('Argument --timeout cannot be less than --target-timeout.')
        errors = True

    if not errors:
        if config['force_services']:
            autorecon.service_scan_semaphore = asyncio.Semaphore(config['max_scans'])
        else:
            autorecon.port_scan_semaphore = asyncio.Semaphore(config['max_port_scans'])
            # If max scans and max port scans is the same, the service scan semaphore and port scan semaphore
            # should be the same object
            if config['max_scans'] == config['max_port_scans']:
                autorecon.service_scan_semaphore = autorecon.port_scan_semaphore
            else:
                autorecon.service_scan_semaphore = asyncio.Semaphore(config['max_scans'] - config['max_port_scans'])

    tags = []
    if isinstance(args.tags, list):
        for tag in args.tags:
            tags.append([tag.lower()])
    else:
        for tag_group in list(set(filter(None, args.tags.lower().split(',')))):
            tags.append(list(set(filter(None, tag_group.split('+')))))
    # Remove duplicate lists from list.
    [autorecon.tags.append(t) for t in tags if t not in autorecon.tags]

    excluded_tags = []
    if args.exclude_tags is None:
        args.exclude_tags = ''
    if args.exclude_tags != '':
        for tag_group in list(set(filter(None, args.exclude_tags.lower().split(',')))):
            excluded_tags.append(list(set(filter(None, tag_group.split('+')))))

        # Remove duplicate lists from list.
        [autorecon.excluded_tags.append(t) for t in excluded_tags if t not in autorecon.excluded_tags]

    if config['port_scans']:
        config['port_scans'] = [x.strip().lower() for x in config['port_scans'].split(',')]

    if config['service_scans']:
        config['service_scans'] = [x.strip().lower() for x in config['service_scans'].split(',')]

    if config['reports']:
        config['reports'] = [x.strip().lower() for x in config['reports'].split(',')]

    raw_targets = args.targets

    if len(args.target_file) > 0:
        if not os.path.isfile(args.target_file):
            logger.error('The target file "' + args.target_file + '" was not found.')
            sys.exit(1)
        try:
            with open(args.target_file, 'r') as f:
                lines = f.read()
                for line in lines.splitlines():
                    line = line.strip()
                    if line.startswith('#'): continue
                    match = re.match('([^#]+)#', line)
                    if match:
                        line = match.group(1).strip()
                    if len(line) == 0: continue
                    if line not in raw_targets:
                        raw_targets.append(line)
        except OSError:
            logger.error('The target file ' + args.target_file + ' could not be read.')
            sys.exit(1)

    for target in raw_targets:
        try:
            ip = ipaddress.ip_address(target)
            ip_str = str(ip)

            found = False
            for t in autorecon.pending_targets:
                if t.address == ip_str:
                    found = True
                    break

            if found:
                continue

            if isinstance(ip, ipaddress.IPv4Address):
                autorecon.pending_targets.append(Target(ip_str, ip_str, 'IPv4', 'ip', autorecon))
            elif isinstance(ip, ipaddress.IPv6Address):
                autorecon.pending_targets.append(Target(ip_str, ip_str, 'IPv6', 'ip', autorecon))
            else:
                logger.fail('This should never happen unless IPv8 is invented.')
        except ValueError:

            try:
                target_range = ipaddress.ip_network(target, strict=False)
                if not args.disable_sanity_checks and target_range.num_addresses > 256:
                    logger.fail(target + ' contains ' + str(
                        target_range.num_addresses) + ' addresses. Check that your CIDR notation is correct. '
                                                      'If it is, re-run with the --disable-sanity-checks option to '
                                                      'suppress this check.')
                    errors = True
                else:
                    for ip in target_range.hosts():
                        ip_str = str(ip)

                        found = False
                        for t in autorecon.pending_targets:
                            if t.address == ip_str:
                                found = True
                                break

                        if found:
                            continue

                        if isinstance(ip, ipaddress.IPv4Address):
                            autorecon.pending_targets.append(Target(ip_str, ip_str, 'IPv4', 'ip', autorecon))
                        elif isinstance(ip, ipaddress.IPv6Address):
                            autorecon.pending_targets.append(Target(ip_str, ip_str, 'IPv6', 'ip', autorecon))
                        else:
                            logger.fail('This should never happen unless IPv8 is invented.')

            except ValueError:

                try:
                    addresses = socket.getaddrinfo(target, None, socket.AF_INET)
                    ip = addresses[0][4][0]

                    found = False
                    for t in autorecon.pending_targets:
                        if t.address == target:
                            found = True
                            break

                    if found:
                        continue

                    autorecon.pending_targets.append(Target(target, ip, 'IPv4', 'hostname', autorecon))
                except socket.gaierror:
                    try:
                        addresses = socket.getaddrinfo(target, None, socket.AF_INET6)
                        ip = addresses[0][4][0]

                        found = False
                        for t in autorecon.pending_targets:
                            if t.address == target:
                                found = True
                                break

                        if found:
                            continue

                        autorecon.pending_targets.append(Target(target, ip, 'IPv6', 'hostname', autorecon))
                    except socket.gaierror:
                        logger.error(target + ' does not appear to be a valid IP address, IP range, or '
                                              'resolvable hostname.')
                        errors = True

    if len(autorecon.pending_targets) == 0:
        logger.error('You must specify at least one target to scan!')
        errors = True

    if config['single_target'] and len(autorecon.pending_targets) != 1:
        logger.error('You cannot provide more than one target when scanning in single-target mode.')
        errors = True

    if not args.disable_sanity_checks and len(autorecon.pending_targets) > 256:
        logger.error('A total of ' + str(
            len(autorecon.pending_targets)) + ' targets would be scanned. If this is correct, re-run with the '
                                              '--disable-sanity-checks option to suppress this check.')
        errors = True

    if not config['force_services']:
        port_scan_plugin_count = 0
        for plugin in autorecon.plugin_types['port']:
            if config['port_scans'] and plugin.slug in config['port_scans']:
                matching_tags = True
                excluded_tags = False
            else:
                matching_tags = False
                for tag_group in autorecon.tags:
                    if set(tag_group).issubset(set(plugin.tags)):
                        matching_tags = True
                        break

                excluded_tags = False
                for tag_group in autorecon.excluded_tags:
                    if set(tag_group).issubset(set(plugin.tags)):
                        excluded_tags = True
                        break

            if matching_tags and not excluded_tags:
                port_scan_plugin_count += 1

        if port_scan_plugin_count == 0:
            logger.error('There are no port scan plugins that match the tags specified.')
            errors = True
    else:
        port_scan_plugin_count = config['max_port_scans'] / 5

    if errors:
        sys.exit(1)

    config['port_scan_plugin_count'] = port_scan_plugin_count

    num_initial_targets = max(1, math.ceil(config['max_port_scans'] / port_scan_plugin_count))

    start_time = time.time()

    pending = []
    i = 0
    while autorecon.pending_targets:
        pending.append(asyncio.create_task(scan_target(autorecon.pending_targets.pop(0))))
        i += 1
        if i >= num_initial_targets:
            break

    if not config['disable_keyboard_control']:
        tty.setcbreak(sys.stdin.fileno())
        keyboard_monitor = asyncio.create_task(tasks.keyboard(autorecon))

    timed_out = False
    while pending:
        done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED, timeout=1)

        # If something failed in scan_target, autorecon.errors will be true.
        if autorecon.errors:
            tasks.cancel_all_tasks(None, None, autorecon, terminal_settings)
            sys.exit(1)

        # Check if global timeout has occurred.
        if config['timeout'] is not None:
            elapsed_seconds = round(time.time() - start_time)
            m, s = divmod(elapsed_seconds, 60)
            if m >= config['timeout']:
                timed_out = True
                break

        for task in done:
            if autorecon.pending_targets:
                pending.add(asyncio.create_task(scan_target(autorecon.pending_targets.pop(0))))
            if task in pending:
                pending.remove(task)

        port_scan_task_count = 0
        for targ in autorecon.scanning_targets:
            for process_list in targ.running_tasks.values():
                # If we're not scanning ports, count ServiceScans instead.
                if config['force_services']:
                    if issubclass(process_list['plugin'].__class__,
                                  ServiceScanPlugin):  # TODO should we really count ServiceScans? Test...
                        port_scan_task_count += 1
                else:
                    if issubclass(process_list['plugin'].__class__, PortScanPlugin):
                        port_scan_task_count += 1

        num_new_targets = math.ceil((config['max_port_scans'] - port_scan_task_count) / port_scan_plugin_count)
        if num_new_targets > 0:
            i = 0
            while autorecon.pending_targets:
                pending.add(asyncio.create_task(scan_target(autorecon.pending_targets.pop(0))))
                i += 1
                if i >= num_new_targets:
                    break

    if not config['disable_keyboard_control']:
        keyboard_monitor.cancel()

    # If there's only one target we don't need a combined report
    if len(autorecon.completed_targets) > 1:
        for plugin in autorecon.plugin_types['report']:
            plugin_tag_set = set(plugin.tags)

            matching_tags = False
            for tag_group in autorecon.tags:
                if set(tag_group).issubset(plugin_tag_set):
                    matching_tags = True
                    break

            excluded_tags = False
            for tag_group in autorecon.excluded_tags:
                if set(tag_group).issubset(plugin_tag_set):
                    excluded_tags = True
                    break

            if matching_tags and not excluded_tags:
                pending.add(asyncio.create_task(generate_report(plugin, autorecon.completed_targets)))

        while pending:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED, timeout=1)

    if timed_out:
        tasks.cancel_all_tasks(None, None, autorecon, terminal_settings)

        elapsed_time = task_utils.calculate_elapsed_time(start_time)
        logger.warn('{byellow}AutoRecon took longer than the specified timeout period (' + str(
            config['timeout']) + ' min). Cancelling all scans and exiting.{rst}')
    else:
        while len(
                asyncio.all_tasks()) > 1:  # this code runs in the main() task so it will be the only task left running
            await asyncio.sleep(1)

        elapsed_time = task_utils.calculate_elapsed_time(start_time)
        logger.info('{bright}Finished scanning all targets in ' + elapsed_time + '!{rst}')
        logger.info(
            '{bright}Don\'t forget to check out more commands to run manually in the _manual_commands.txt file in '
            'each target\'s scans directory!')
    if autorecon.missing_services:
        logger.warn(
            '{byellow}AutoRecon identified the following services, but could not match them to any plugins based on '
            'the service name. Please report these to Tib3rius: ' + ', '.join(
                autorecon.missing_services) + '{rst}')

    if not config['disable_keyboard_control']:
        # Restore original terminal settings.
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, terminal_settings)


def cancel_all_tasks(sig, frame):
    return task_utils.cancel_all_tasks(sig, frame, autorecon, terminal_settings)


def main():
    # Capture Ctrl+C and cancel everything.
    signal.signal(signal.SIGINT, cancel_all_tasks)
    try:
        asyncio.run(run())
    except asyncio.exceptions.CancelledError:
        pass
    except RuntimeError:
        pass


if __name__ == '__main__':
    main()
