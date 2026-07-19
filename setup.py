from setuptools import setup, find_packages

setup(
    name="webscanner",
    version="1.0.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "httpx>=0.25.0",
    ],
    entry_points={
        "console_scripts": [
            "webscanner=webscanner.main:main",
        ],
    },
)
