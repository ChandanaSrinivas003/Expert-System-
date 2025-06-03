import os
import binascii
secKey = binascii.hexlify(os.urandom(24))
print(secKey)