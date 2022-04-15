from setuptools import setup

setup(
    name='vulnman_scanner',
    version='0.0.1',
    packages=['vulnman', 'vulnman.api', 'vulnman.conf', 'vulnman.core', 'vulnman.core.utils', 'vulnman.core.assets',
              'vulnman.parsers', 'vulnman.parsers.plugins', 'vulnman.scanner', 'vulnman.scanner.tasks',
              'vulnman.scanner.utils', 'vulnman.scanner.plugins', 'vulnman.scanner.plugins.core',
              'vulnman.scanner.plugins.default'],
    url='https://github.com/vulnman/vulnman-scanner',
    package_data={"vulnman": ["config.yaml"]},
    license='GPL-3.0',
    scripts=["bin/vulnmanscanner"],
    author='blockomat2100',
    author_email='',
    description='A vulnerability scanner for vulnman'
)
