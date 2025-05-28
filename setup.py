from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext


class OptionalBuildExt(build_ext):
    """Allow C extension building to fail without aborting the install."""

    def run(self):
        try:
            super().run()
        except Exception:
            print("C extension build failed, using Python fallback.")

    def build_extension(self, ext):
        try:
            super().build_extension(ext)
        except Exception:
            print(f"Building extension {ext.name} failed, skipping.")


ext_modules = []
try:
    ext_modules.append(
        Extension(
            "AcraNetwork.IRIG106.Chapter7.golay_c",
            ["AcraNetwork/IRIG106/Chapter7/golay_c.c"],
            language="c",
        )
    )
except Exception:
    pass  # Ignore if setup fails to define extension


# Load configuration from setup.cfg
setup(
    ext_modules=ext_modules,
    cmdclass={"build_ext": OptionalBuildExt},
)
