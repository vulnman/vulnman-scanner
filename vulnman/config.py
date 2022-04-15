import os
# Legacy from autorecon
# TODO: move to our own YAML based config
configurable_keys = [
    'ports',
    'max_scans',
    'max_port_scans',
    'tags',
    'exclude_tags',
    'port_scans',
    'service_scans',
    'reports',
    'output',
    'single_target',
    'only_scans_dir',
    'no_port_dirs',
    'heartbeat',
    'timeout',
    'target_timeout',
    'nmap',
    'nmap_append',
    'disable_sanity_checks',
    'disable_keyboard_control',
    'force_services',
    'max_plugin_target_instances',
    'max_plugin_global_instances',
    'accessible',
    'verbose',
    'custom_plugins'
]


configurable_boolean_keys = [
    'single_target',
    'only_scans_dir',
    'no_port_dirs',
    'disable_sanity_checks',
    'accessible'
]


config = {
    'protected_classes': [
        'target', 'service', 'commandstreamreader',
        'plugin', 'portscan', 'servicescan', 'global',
        'pattern'
    ],
    'config_dir': "",
    'global_file': None,
    'ports': None,
    'max_scans': 50,
    'max_port_scans': None,
    'tags': 'default',
    'exclude_tags': None,
    'port_scans': None,
    'service_scans': None,
    'reports': None,
    'output': 'results',
    'single_target': False,
    'only_scans_dir': False,
    'no_port_dirs': False,
    'heartbeat': 60,
    'timeout': None,
    'target_timeout': None,
    'nmap': '-vv --reason -Pn -T4',
    'nmap_append': '',
    'disable_sanity_checks': False,
    'disable_keyboard_control': False,
    'force_services': None,
    'max_plugin_target_instances': None,
    'max_plugin_global_instances': None,
    'accessible': False,
    'custom_plugins': [],
    'verbose': 0,
    'base_dir': os.path.join(os.path.dirname(os.path.dirname(__file__)), "vulnman")
}
