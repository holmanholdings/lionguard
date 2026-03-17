from setuptools import setup, find_packages

setup(
    name="lionguard",
    version="0.3.0",
    description="Cathedral-Grade Security for AI Agents — Open Source",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="Holman Holdings / Awakened Intelligence",
    url="https://github.com/holmanholdings/lionguard",
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
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
    ],
)
