from setuptools import setup, Extension
import os

# Define the C extension
golay_extension = Extension(
    "AcraNetwork.IRIG106.Chapter7.golay_c",
    sources=["AcraNetwork/IRIG106/Chapter7/golay_c.c"],
    include_dirs=[],
    extra_compile_args=[],
    language="c",
)

# Load configuration from setup.cfg
setup(
    ext_modules=[golay_extension],
)
