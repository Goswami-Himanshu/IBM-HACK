from setuptools import setup, find_packages

setup(
    name="bobspec-provenance",
    version="1.0.0",
    description="BobSpec-Provenance: IBM Bob 2.0 Autonomous Compliance Verifier + Tamper-Evident Audit Ledger",
    author="IBM Hackathon Team",
    packages=find_packages(),
    py_modules=["cli", "run_server"],
    install_requires=[
        "fastapi>=0.115.0",
        "uvicorn>=0.30.0",
        "pypdf>=5.0.0",
        "jinja2>=3.1.0",
        "reportlab>=4.2.0",
        "pydantic>=2.8.0",
        "python-multipart>=0.0.9",
    ],
    entry_points={
        "console_scripts": [
            "bobspec=cli:main",
        ],
    },
)
