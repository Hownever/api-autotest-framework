#!/bin/env python
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# See LICENSE for more details.
#
# Copyright: JD Inc. 2019
# Authors: likui <likui34@jd.com>

from setuptools import setup, find_packages


setup(name='avocado-framework-plugin-jdcloud-sdk-golang',
      description='Avocado Plugin for Execution of jdcloud sdk Golang tests',
      version=open("VERSION", "r").read().strip(),
      author='likui',
      author_email='likui34@jd.com',
      url='http://www.jdcloud.com/',
      packages=find_packages(),
      include_package_data=True,
      install_requires=['avocado-framework'],
      entry_points={
          'avocado.plugins.cli': [
              'jdcloud_sdk_go = avocado_jdcloud_sdk_golang:GolangCLI',
          ]}
      )
