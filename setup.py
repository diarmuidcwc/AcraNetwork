#!/usr/bin/env python

from distutils.core import setup
import shutil
from AcraNetwork.__version__ import __version__

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(name='AcraNetwork',
      version=__version__,
      description='Classes and utilities to support Flight Test Instrumentation Ethernet networks',
      author='Diarmuid Collins',
      author_email='dcollins@curtisswright.com',
      url='https://github.com/diarmuidcwc/AcraNetwork',
      packages=['AcraNetwork'],
      scripts=['examples/tx_inetx_udp.py', 'examples/validate_pcap.py', 'examples/pkg_gen.ini'],
      long_description="A collection of classes that can be used to decom network or PCM based FTI traffic",
      classifiers =['Programming Language :: Python',
                    'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
                    'Operating System :: OS Independent',
                    'Development Status :: 3 - Alpha',
                    'Intended Audience :: Developers',
                    'Topic :: Software Development :: Libraries :: Python Modules',
                    ],
     )
