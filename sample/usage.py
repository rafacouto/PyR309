#!/usr/bin/python

import fingerprint.r309
import os
import time

# import the module
r309 = fingerprint.r309.R309()

port = os.getenv('FINGERPRINT_PORT', "/dev/ttyUSB1")

if not r309.connect(port):
	raise Exception("Fingerprint sensor not connected in %s." % port)

print("Security level (1-5): %i" % r309.getSecurityLevel())
print("Storage capacity: %i" % r309.getStorageCapacity())
print("Next template number: %i" % r309.getNextTemplateNumber())

while True:
	result = r309.scanFinger()
	if result['success']:
		print("Finger detected and scanned.")
	else:
		if result['code'] == 2:
			# finger not detected
			print(".")
		else:
			# finger detected but error with template
			print(result['message'])
	time.sleep(1);


