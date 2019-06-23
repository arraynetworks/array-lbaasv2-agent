#!/usr/bin/env python
# flake8: noqa

from setuptools import setup, find_packages

setup(
    name = "array-lbaasv2-agent",
    version = "1.0.0",
    packages = find_packages(),

    author = "Array Networks",
    author_email = "wangli2@arraynetworks.com.cn",
    description = "Array Networks Openstack LBaaS v2 Agent",
    license = "Apache",
    keywords = "array apv slb load balancer openstack neutron lbaas",
    url = "http://www.arraynetworks.com.cn",

    data_files=[('/etc/neutron/conf.d/neutron-server', ['etc/neutron/conf.d/neutron-server/arraynetworks.conf']),
                ('/usr/lib/systemd/system/', ['etc/systemd/array-lbaasv2-agent.service']), ],

    classifiers = [
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Topic :: Internet',
    ],

    entry_points={
        'console_scripts': [
            'array-lbaasv2-agent = array_lbaasv2_agent.v2.agent:main'
        ]
    },

)
