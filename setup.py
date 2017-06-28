#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup


setup(
    name="Time Authentication",
    version='1.0',
    description='Python package to exploit time based authentication faster',
    author='Erwan Dupard',
    author_email='sakiirlessons@gmail.com',
    url='https://github.com/SakiiR/timeauth',
    install_requires=[
        'pwntools==3.5.1'
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Information Security :: Penetration Testing Tool',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.5',
    ],
    packages=[]
)
