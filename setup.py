#!/usr/bin/env python

from distutils.core import setup
import shutil

with open("README.md", "r") as fh:
    long_description = fh.read()

exec(open('AcraNetwork/__version__.py').read())

setup(name='AcraNetwork',
      version=__version__,
      description='Classes and utilities to support Flight Test Instrumentation Ethernet networks',
      author='Diarmuid Collins',
      author_email='dcollins@curtisswright.com',
      url='https://github.com/diarmuidcwc/AcraNetwork',
      packages=['AcraNetwork'],
      scripts=['examples/validate_fast_seq.py', 'examples/validate_pcap.py'],
      long_description="A collection of classes that can be used to decom network or PCM based FTI traffic",
      classifiers =['Programming Language :: Python',
                    'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
                    'Operating System :: OS Independent',
                    'Development Status :: 3 - Alpha',
                    'Intended Audience :: Developers',
                    'Topic :: Software Development :: Libraries :: Python Modules',
                    ],
     )
