# AesOracle - AES Encryption without a Key

This is an example implementation of a Padding Oracle algorithm for both
decrypting and encrypting data.

Disclaimer:  This module was written for educational purposes to accompany
my LinkedIn article "AES Encrypt without a Key?".  Please do not attempt
to use this code or information on or against any system for 
which you do not have explicit authorization from the owner.
I shall not be held responsible for your actions.

## Prerequisites

### AesOracle

Python 3 is about all you need to use the encryption and decryption oracle
engine.  You will need a vulnerable server which is included in this
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

The test server puts out a lot of info so you can watch progress.  Each request represents an IV+CT block pair where the server is helping us decrypt the CT
based on its oracle.

# Hack Ethically

'nough said.

