from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    # PyPI distribution name; `dmp` is already taken on PyPI by an
    # unrelated package, so we publish under the product brand instead.
    # The import path stays `import dmp` — distribution name and
    # import name intentionally differ (same pattern as pyyaml → yaml).
    name="dnsmesh",
    version="0.3.6",
    author="Oscar Valenzuela B",
    author_email="oscar.valenzuela.b@gmail.com",
    description="A federated end-to-end encrypted messaging protocol delivered over DNS",
    long_description=long_description,
    long_description_content_type="text/markdown",
    # Ship only the `dmp` package tree; bare `find_packages()` otherwise
    # pulls `tests/` into site-packages and collides with every other
    # project that also has a top-level `tests` module.
    packages=find_packages(include=("dmp", "dmp.*")),
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
            "pytest-timeout>=2.0",
            "black>=23.0.0",
            "mypy>=1.0.0",
            "pylint>=2.17.0",
            # Property-based fuzz harness for wire parsers (tests/fuzz/).
            # Required to collect the test suite — CI runs
            # `pip install -e .[dev]` and will fail to collect fuzz
            # modules without it.
            "hypothesis>=6.0",
            # Supply-chain toolchain: pip-compile generates the hashed
            # lockfiles (requirements.lock / requirements-dev.lock);
            # pip-audit scans for known CVEs in CI.
            "pip-tools>=7.0",
            "pip-audit>=2.6",
        ]
    },
    entry_points={
        "console_scripts": [
            # Distribution is `dnsmesh` on PyPI; import path stays `dmp`
            # (same split as pyyaml → yaml). The `dmp` command name was
            # avoided because an unrelated `dmp` package on PyPI ships a
            # binary of that name and the two would collide on $PATH.
            "dnsmesh = dmp.cli:main",
            "dnsmesh-node-admin = dmp.server.admin:main",
        ],
    },
)