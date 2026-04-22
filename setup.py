from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="dmp",
    version="0.1.0",
    author="Oscar Valenzuela B",
    author_email="oscar.valenzuela.b@gmail.com",
    description="A federated end-to-end encrypted messaging protocol delivered over DNS",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    license="AGPL-3.0",
    python_requires=">=3.10",
    url="https://github.com/oscarvalenzuelab/DNSMeshProtocol",
    install_requires=[
        "cryptography>=41.0.0",
        "dnspython>=2.4.0",
        "reedsolo>=1.7.0",
        "pyyaml>=6.0",
        "asyncio-throttle>=1.0.0",
        "requests>=2.28.0",
        "boto3>=1.26.0",
        "argon2-cffi>=23.1.0",
        "zfec>=1.5.7",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0",
            "black>=23.0.0",
            "mypy>=1.0.0",
            "pylint>=2.17.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "dmp = dmp.cli:main",
        ],
    },
)