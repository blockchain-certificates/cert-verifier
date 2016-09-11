[![Build Status](https://travis-ci.org/blockchain-certificates/cert-verifier.svg?branch=master)](https://travis-ci.org/blockchain-certificates/cert-verifier)
[![PyPI version](https://badge.fury.io/py/cert-verifier.svg)](https://badge.fury.io/py/cert-verifier)

# cert-verifier
Library for verifying blockchain certificates.

## Using the pypi package

The most common way to use this is to add the [latest cert-verifier pypi package](https://badge.fury.io/py/cert-verifier) to your project dependencies. 


## Running the CLI locally

1. Ensure you have an python environment. [Recommendations](blockchain-certificates.github.io/docs/virtualenv.md)

1. Git clone the repository and change to the directory

  ```bash
  git clone https://github.com/blockchain-certificates/cert-verifier.git && cd cert-verifier
  ```

2. Run cert-viewer setup

  ```bash
  pip install .
  ```

3. Run the main program

  ```bash
  cd cert_verifier
  python verifier.py
  ```

## Unit tests

This project uses tox to validate against several python environments.

```shell
# ensure your virtual python environment is activated (example)
source ./venv/bin/activate

# run tests
./run-tests.sh
