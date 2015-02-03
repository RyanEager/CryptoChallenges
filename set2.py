import set1, util, os, random

# 9
def PKCSencode(string,padTo):

	padNum = padTo - len(string)
	return string +  bytearray([padNum] * padNum)

def PKCSdecode(string):
	return string[:(len(string) - string[-1])]



#10
def CBCdecrypt(key, IV, ciphertext):
	plaintext = ""
	for x in range(32,len(ciphertext)+32,32):
		 plaintext += util.xor(IV, set1.AESinECBdecrypt(key,util.b16decode(ciphertext[x-32:x])))
		 IV = util.b16decode(ciphertext[x-32:x])
	
	return plaintext

def CBCencrypt(key, IV, plaintext):
	bytes = util.b16encode(plaintext)
	ciphertext = ""
	for x in range(32,len(plaintext)+32,32):
		 IV = set1.AESinECBencrypt(key, util.xor(IV, util.b16decode(bytes[x-32:x])))
		 ciphertext += IV
	
	return ciphertext

#11
def ECB_CBC_encryption_oracle(usrInput):

	# 5-10 bytes of rand data | plaintext | 5-10 bytes rand data
	plaintext = os.urandom(random.randint(5,10)) + usrInput + os.urandom(random.randint(5,10))

	# pad plaintext out to the 16-byte AES block size 
	plaintext = str(PKCSencode(plaintext,(16 - (len(plaintext) % 16) + len(plaintext))))

	# encrypt under ECB 1/2 the time, and under CBC the other half
	if random.randint(1,2) % 2 == 0:
		# ECB
		mode = "ECB"
		cipherText = set1.AESinECBencrypt(os.urandom(16), plaintext)
	else:
		# CBC
		mode = "CBC"
		cipherText = CBCencrypt(os.urandom(16), os.urandom(16), plaintext)

	# inital guess
	guess = "CBC"

	# encode to Hex for easy pattern recongintion 
	cipherText = util.b16encode(cipherText)

	# take ciphertext 8 bytes at a time
	for x in range(0,len(cipherText)-16):
		# if that 8 bytes repeate we are most likely in ECB mode
		if cipherText.count(cipherText[x:x+16]) > 1:
			guess = "ECB"
			break

	return ( guess, mode)
	


if __name__ == '__main__':
	# TEST for #9
	print "## 9 PKCS7 Padding ## \n"

	string = "YELLOW SUBMARINE"
	padTo = 20
	encoded = PKCSencode(string, padTo)
	decoded = PKCSdecode(encoded)
	print repr(encoded)
	print repr(decoded)

	# TEST for #10
	print "## 10 PKCS7 AES in CBC ## \n"
	key = "YELLOW SUBMARINE"
	IV = '\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'

	# Open file and read contents into single buffer
	with open('10.txt') as f:
	    data=''.join(util.b64tob16(line.strip()) for line in f)

	print CBCdecrypt(key, IV, data)

	# TEST for #11

	print "## 11 ECB/CBC dection orcale ## \n"

	correct = 0
	incorrect = 0

	print "Test 1,000 random cases..."

	for x in range(0,1000):
		out = ECB_CBC_encryption_oracle("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
		if out[0] == out[1]:
			correct += 1
		else:
			incorrect += 1

	print "Correct Guesses:", correct
	print "Incorrect Guesses:", incorrect