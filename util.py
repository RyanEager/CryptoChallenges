# Using PyCrypto from: https://www.dlitz.net/software/pycrypto/

from Crypto.Cipher import XOR
import base64

def b64decode(num):
	return base64.standard_b64decode(num)

def b64encode(num):
	return base64.standard_b64encode(num)

def b16decode(num):
	return base64.b16decode(num)

def b16encode(num):
	return base64.b16encode(num)

def b64tob16(num):
	return base64.b16encode(base64.standard_b64decode(num))

def b16tob64(num):
	return base64.standard_b64encode(base64.b16decode(num))

def xor(str1, str2):
	return XOR.XORCipher.encrypt(XOR.new(str1), str2)
