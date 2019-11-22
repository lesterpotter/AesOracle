# AesOracle Package

An example implementation of a Padding Oracle algorithm for both
decrypting and encrypting data.

## Prerequisites

### AesOracle

Python 3 is about all you need to use the encryption and decryption oracle
engine.  You will need a vulnerable server which in included in the
repository.

### AesOracleServer

You will need bubble and pycryptodome (or pycrypto compatible library) if you
use this program as is.  Of course, modify it to suite your needs.  Just
be aware that AesOracle's test functionality expects the particular oracle
that this vulnerable server exposes.

## How to Install

(cd AesOracle; python setup.py install)

## How to Run

Open two terminals.

In one, (cd AesOracleServer; python AesOracleServer.py)

In the other, (cd AesOracle; python AesOracle.py)

Or run:  python ExploitOracle.py

## How to Write Your Own Exloit

Read the source code for ExploitOracle.py.  You will need a vulnerable server
and some sort of query or post that you can do to reveal padding errors, and
your client will need to implement and supply the PaddingOracle function.

