from setuptools import setup, find_packages

setup(
    name="cryptvault",
    version="1.1.0",
    description="Zero-Trust Encrypted File Storage with Cybersecurity Tooling",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="Ayanokoji",
    license="MIT",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "cryptography>=41.0.0",
        "pyotp>=2.8.0",
        "click>=8.1.0",
        "fastapi>=0.100.0",
        "uvicorn[standard]>=0.22.0",
        "python-multipart>=0.0.6",
        "jinja2>=3.1.2",
        "qrcode>=7.4",
        "rich>=13.0.0",
    ],
    entry_points={
        "console_scripts": [
            "cryptvault=cryptvault.cli.main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography",
    ],
)
