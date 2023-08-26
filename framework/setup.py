from setuptools import setup, find_packages
import os
ROOT_DIR = os.path.abspath(os.path.dirname(__file__))

def read_version():
    parent_directory = os.path.dirname(ROOT_DIR)
    version = os.path.join(parent_directory, "VERSION")
    with open(version, 'r') as file:
        version_ = file.read()

    return version_


setup(
    name='idasync',
    version=read_version(),
    packages=find_packages(),
    author='thibault poncetta',
    entry_points={
        'console_scripts': [
            'idasync=idasync:main',
        ],
    },
    summary='Utility Server to Work on multiple IDA instances',
)

