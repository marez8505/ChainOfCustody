"""
Setup configuration for ChainOfCustody.

Author: Edward Marez
License: MIT
"""

from setuptools import setup, find_packages
from pathlib import Path

long_description = (Path(__file__).parent / "README.md").read_text(encoding="utf-8")

setup(
    name="chainofcustody",
    version="1.0.0",
    author="Edward Marez",
    description=(
        "Digital Evidence Chain of Custody Management System — "
        "forensic hash verification, tamper-evident audit trails, "
        "and court-ready report generation."
    ),
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="MIT",
    python_requires=">=3.10",
    packages=find_packages(exclude=["tests", "tests.*"]),
    package_data={
        "chainofcustody": ["form_templates/*.html"],
    },
    install_requires=[
        "jinja2>=3.1.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "chainofcustody=chainofcustody.main:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Legal Industry",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Office/Business :: Groupware",
        "Operating System :: OS Independent",
    ],
    keywords=(
        "forensics digital-evidence chain-of-custody FBI CART "
        "evidence-management hash-verification tamper-detection"
    ),
)
