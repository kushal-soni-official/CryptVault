from setuptools import setup, find_packages

setup(
    name="cryptvault",
    version="1.0.0",
    description="Encrypted File Storage System with Security Tooling",
    packages=find_packages(),
    install_requires=[
        "cryptography>=41.0.0",
        "pyotp>=2.8.0",
        "click>=8.1.0",
        "typer>=0.9.0",
        "fastapi>=0.100.0",
        "uvicorn[standard]>=0.22.0",
        "python-multipart>=0.0.6",
        "jinja2>=3.1.2",
        "python-nmap>=0.7.1",
        "requests>=2.31.0",
        "scapy>=2.5.0",
    ],
    entry_points={
        "console_scripts": [
            "cryptvault=cryptvault.cli.main:main",
        ],
    },
)
