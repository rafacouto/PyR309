# R309 python module

A comprehensive library to use fingerprint sensors with R309 protocol.

## Quick start

Change directory to the root of the project (where this README.md is located)
and set these environment variables (adjust FINGERPRINT\_PORT where your
fingerprint is connected to):

	export FINGERPRINT_PORT=/dev/ttyUSB0
	export PYTHONPATH=$(pwd)

## Samples

It is assumed your fingerprint sensor is set with factory defaults (address
and password).

### usage.py

```
$ sample/usage.py 
Security level (1-5): 3
Storage capacity: 1000
Next template number: 0
.
.
Finger detected and scanned.

```
