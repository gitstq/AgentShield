"""AgentShield - A lightweight AI Agent policy governance engine."""

from setuptools import setup, find_packages

setup(
    name="agentshield",
    version="1.0.0",
    description="A lightweight AI Agent policy governance engine",
    long_description=open("README.md").read() if __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    author="AgentShield Team",
    author_email="team@agentshield.dev",
    url="https://github.com/agentshield/agentshield",
    license="MIT",
    packages=find_packages(exclude=["tests*", "examples*"]),
    python_requires=">=3.8",
    install_requires=[
        "pyyaml>=5.4",
    ],
    extras_require={
        "dashboard": [
            "flask>=2.0",
        ],
        "dev": [
            "flask>=2.0",
            "pyyaml>=5.4",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    entry_points={
        "console_scripts": [
            "agentshield=agentshield.dashboard.app:run_dashboard",
        ],
    },
)
