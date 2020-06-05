import os
import uuid

from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))


with open('requirements.txt') as f:
    install_reqs = f.readlines()
    reqs = [str(ir) for ir in install_reqs]

with open(os.path.join(here, 'README.md')) as fp:
    long_description = fp.read()

setup(
    name='cert-verifier',
    version='2.0.15',
    description='Verifies blockchain certificates',
    author='Blockcerts',
    tests_require=['tox'],
    url='https://github.com/blockchain-certificates/cert-verifier',
    license='MIT',
    author_email='info@blockcerts.org',
    long_description=long_description,
    packages=find_packages(),
    install_requires=reqs
)
