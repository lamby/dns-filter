from setuptools import setup

setup(
    name='dns-filter',

    url='https://chris-lamb.co.uk/projects/dns-filter',
    version='1.0.0',
    description="A simple DNS proxy that returns NXDOMAIN if the master "
        "offers an IP from a specified blacklist.",

    author="Chris Lamb",
    author_email='chris@chris-lamb.co.uk',

    scripts=(
        'dns-filter',
    ),
)
