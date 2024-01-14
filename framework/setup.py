from setuptools import setup, find_packages
import os
ROOT_DIR = os.path.abspath(os.path.dirname(__file__))

def read_version():
    parent_directory = os.path.dirname(ROOT_DIR)
    print(parent_directory)
    version = os.path.join(parent_directory, "VERSION")
    with open(version, 'r') as file:
        version_ = file.read()

    return version_


setup(
    name='idasyncserver',
    version="1.3.01.13.2024",
    packages=find_packages(),
    author='thibault poncetta',
    entry_points={
        'console_scripts': [
            'idasyncserver=idasyncserver:main',
        ],
    },
    summary='Utility Server to Work on multiple IDA instances',
    requires=["fastapi", "uvicorn","httpx"]
)

