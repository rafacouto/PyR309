#!/usr/bin/python

from fingerprint.r309 import R309
import os
import time

r309 = R309()

port = os.getenv('FINGERPRINT_PORT', "/dev/ttyUSB0")

if not r309.connect(port):
    raise Exception("Fingerprint sensor not connected in %s." % port)

print("Put the finger to enroll...")

while True:

    result = r309.scanFinger()
    if result['success']:

        print("Finger detected.")

        result = r309.identify(1)
        if result['code'] == R309.CODE_OK:

            # match
            print("Template already registered (#%i, accuracy %i)." % result['match'], result['score'])
            break

        else:

            print("Put the same finger again...")
            result = r309.scanFinger()

            # ToDo
            result = r309.identify(2)

    else:

        if result['code'] == R309.CODE_NO_FINGER:
            # finger not detected
            print(".")

        else:
            # finger detected but error with template
            print(result['message'])

    time.sleep(1);


