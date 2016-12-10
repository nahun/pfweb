"""
pfweb
-----

pfweb is a python web application to manage the OpenBSD Packet Filter (PF). It 
uses *py-pf* to interface with PF and Flask for the web framework. The look 
and feel is based on pfSense and a lot of the ideas are ripped off from them.

pfweb is designed with few dependencies and strives to use only included Python
modules.

The source is on `GitHub <https://github.com/nahun/pfweb>`_
"""
from setuptools import setup, find_packages

requires = [
    'py-pf>=0.1.7',
    'Flask',
    'flask-login'
    ]

setup(name='pfweb',
    version='0.1.0dev4',
    description='Simple web interface for the OpenBSD Packet Filter',
    long_description=__doc__,
    license='BSD',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Intended Audience :: System Administrators',
        'Operating System :: POSIX :: BSD :: OpenBSD',
        'Programming Language :: Python :: 2.7',
        'Framework :: Flask',
        'Topic :: System :: Networking :: Firewalls'
    ],
    author='Nathan Wheeler',
    author_email='nate.wheeler@gmail.com',
    url='https://github.com/nahun/pfweb',
    packages=find_packages(),
    install_requires=requires,
    include_package_data=True,
    zip_safe=False
)
