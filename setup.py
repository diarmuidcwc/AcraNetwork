#!/usr/bin/env python

from distutils.core import setup
import shutil

try:
    from pypandoc import convert
    output = convert('README.md', 'rst', outputfile="README.txt")
except ImportError:
    print("warning: pypandoc module not found, could not convert Markdown to RST")
    shutil.copyfile("README.md","README.txt")

exec(open('AcraNetwork/__version__.py').read())

setup(name='AcraNetwork',
      version=__version__,
      description='Classes and utilities to support Flight Test Instrumentation Ethernet networks',
      author='Diarmuid Collins',
      author_email='dcollins@curtisswright.com',
      url='https://github.com/diarmuidcwc/AcraNetwork',
      packages=['AcraNetwork'],
      long_description=open('README.txt', 'rt').read(),
      classifiers =['Programming Language :: Python',
                    'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
                    'Operating System :: OS Independent',
                    'Development Status :: 3 - Alpha',
                    'Intended Audience :: Developers',
                    'Topic :: Software Development :: Libraries :: Python Modules',
                    ],
     )
