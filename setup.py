#! /usr/bin/env python

# This file is part of Sibyl.
# Copyright 2014 - 2017 Camille MOUGEY <camille.mougey@cea.fr>
#
# Sibyl is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Sibyl is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
# License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Sibyl. If not, see <http://www.gnu.org/licenses/>.

from distutils.core import setup

setup(
    name='sibyl',
    version='0.1',
    author='Camille MOUGEY',
    author_email='commial@gmail.com',
    url='https://github.com/cea-sec/sibyl',
    download_url='https://github.com/cea-sec/sibyl/tarball/master',
    license='GPLv3+',
    description='A Miasm2 based function divination',
    long_description="""
Sibyl is a tool aiming at recognizing functions in binaries based on their side
    effects, by running them in a sandboxed environment.""",
    keywords=["reverse engineering", "emulation"],
    install_requires=[
        'miasm2',
    ],
    packages=['sibyl', 'sibyl/abi', 'sibyl/engine', 'sibyl/learn',
              'sibyl/learn/tracer', 'sibyl/learn/generator',
              'sibyl/heuristics', 'sibyl/test', 'sibyl/actions'],
    scripts=['bin/sibyl'],
)
