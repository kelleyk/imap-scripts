# -*- encoding: utf-8 -*-

from setuptools import setup


setup(
    name='imap-scripts',
    version='0.0.1',
    # description='',
    author='Kevin Kelley',
    author_email='kelleyk@kelleyk.net',
    url='http://github.com/kelleyk/imap-scripts',
    packages=['imap_scripts'],
    install_requires=[
    ],
    entry_points=dict(
        console_scripts=[
            'imap-get-correspondents = imap_scripts:main_get_correspondents',
        ],
    ),
)
