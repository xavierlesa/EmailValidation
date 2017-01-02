# -*- coding:utf8 -*-
#
# Copyright (c) 2014 Xavier Lesa <xavierlesa@gmail.com>.
# All rights reserved.
# Distributed under the BSD license, see LICENSE
from setuptools import setup, find_packages
import sys, os

version = '0.1'
author = 'Xavier Lesa <xavier@link-b.com>'

setup(name='emailvalidation', 
        version=version, 
        description="App para validar emails via MX",
        packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
        include_package_data=True,
        install_requires=[
            'pyDNS',
            'validate-email',
        ],
        zip_safe=False,
        author='Xavier Lesa',
        author_email='xavierlesa@gmail.com',
        url='http://github.com/ninjaotoko/emailvalidation'
        )
