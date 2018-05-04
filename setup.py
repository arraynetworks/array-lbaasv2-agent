#!/usr/bin/env python
# flake8: noqa

from setuptools import setup, find_packages
from setuptools.command.install import install
import os

ARRAY_MAPPING_APV = '/usr/share/array_lbaasv2_agent/mapping_apv.json'
ARRAY_MAPPING_AVX = '/usr/share/array_lbaasv2_agent/mapping_avx.json'

class PostInstallCommand(install):
    def run(self):
        install.run(self)
        os.chmod(ARRAY_MAPPING_APV, 0777)
        os.chmod(ARRAY_MAPPING_AVX, 0777)

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
                ('/usr/lib/systemd/system/', ['etc/systemd/array-lbaasv2-agent.service']),
                ('/usr/share/array_lbaasv2_agent/', ['conf/mapping_apv.json', 'conf/mapping_avx.json']),],

    classifiers = [
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Topic :: Internet',
    ],

    cmdclass={
        'install': PostInstallCommand,
    },

    entry_points={
        'console_scripts': [
            'array-lbaasv2-agent = array_lbaasv2_agent.v2.agent:main'
        ]
    },

)
