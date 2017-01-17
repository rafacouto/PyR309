#!/usr/bin/python

import pyR309
import time

r309 = pyR309.PyR309()

if not r309.connect("/dev/ttyS1"):
	raise Exception("Fingerprint sensor not connected.")

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


