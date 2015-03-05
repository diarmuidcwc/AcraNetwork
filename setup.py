#!/usr/bin/env python

from distutils.core import setup

setup(name='AcraNetwork',
      version='0.2',
      description='Classes and utilities to support Flight Test Instrumentation Ethernet networks',
      author='Diarmuid Collins',
      author_email='dcollins@curtisswright.com',
      url='https://github.com/diarmuidcwc/AcraNetwork',
      packages=['AcraNetwork'],
      long_description=open('README.md', 'rt').read(),
      classifiers =['Programming Language :: Python',
                    'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
                    'Operating System :: OS Independent',
                    'Development Status :: 3 - Alpha',
                    'Intended Audience :: Developers',
                    'Topic :: Software Development :: Libraries :: Python Modules',
                    ],
     )