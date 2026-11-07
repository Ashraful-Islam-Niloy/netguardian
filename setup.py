from setuptools import find_packages, setup

setup(
    name="netguardian",
    version="0.1.0",
    description="A home network device guardian for Windows 10/11",
    packages=find_packages(include=["netguardian", "netguardian.*"]),
    install_requires=["rich>=13.7"],
    entry_points={"console_scripts": ["netguardian=netguardian.cli:main"]},
    python_requires=">=3.10",
)
