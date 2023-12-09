#!/usr/bin/env python3

from setuptools import setup, find_packages


requirements = [line.strip() for line in open('requirements.txt').readlines()]

setup(
    name='d1kit',
    version='0.1.0',
    # description='',
    # py_modules=['foo'],
    # packages=['foobar', 'foobar.subfoo'],
    packages=find_packages(),  # __init__.py folders search
    # packages=find_packages(exclude=('__init__', 'setup',)),
    # packages=find_packages(include=('zreprt', 'fd')),
    python_requires='>=3.10',
    install_requires=requirements,
)


# This file is written to make use of dev-friendly editable installs.
# > PEP 517 doesn't support editable installs so absense of `setup.py`
# > is currently incompatible with `pip install -e .`.
# --- https://setuptools.pypa.io/en/latest/setuptools.html
