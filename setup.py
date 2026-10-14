import re
from pathlib import Path

from setuptools import setup, find_packages

_init = (Path(__file__).resolve().parent / "lionguard" / "__init__.py").read_text(encoding="utf-8")
_version = re.search(r'^__version__\s*=\s*[\'"]([^\'"]+)[\'"]', _init, re.M)
if _version is None:
    raise RuntimeError("lionguard/__init__.py is missing __version__")

setup(
    name="lionguard",
    version=_version.group(1),
    description="Cathedral-Grade Security for AI Agents — Open Source",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="Holman Holdings / Awakened Intelligence",
    license="MIT",
    url="https://github.com/holmanholdings/lionguard",
    project_urls={
        "Source": "https://github.com/holmanholdings/lionguard",
        "Changelog": "https://github.com/holmanholdings/lionguard/blob/v0.35.0/README.md#changelog",
    },
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "requests>=2.28.0",
    ],
    entry_points={
        "console_scripts": [
            "lionguard=lionguard.cli.main:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Programming Language :: Python :: 3",
    ],
)
