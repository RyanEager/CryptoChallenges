from Crypto.Cipher import XOR, AES
from operator import itemgetter
import util, FrequencyFinder, sys, base64


## 1 Convert to base64 and back ##
# in util.py


## 2 Fixed XOR ##
def xor(input1, input2):
	return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(input1, input2)).encode("hex")

## 3 Single-byte XOR Cipher ##
def SBXdecipher(cipherText):
	
	plaintext = []
	scores = []

	# All Letters, Numbers, and Symbols
	for x in range(32,127):
		# XOR cipherText against ascii chars
		plaintext.append(util.xor(str(unichr(x)), cipherText))

	    	scores.append(FrequencyFinder.englishFreqMatchScore(plaintext[x-32]))

		# Count frequency of most common letters and spaces
		# eFrequency= plaintext[x].count('e') / float(len (plaintext[x]))
		# tFrequency= plaintext[x].count('t') / float(len (plaintext[x]))
		# aFrequency= plaintext[x].count('a') / float(len (plaintext[x]))
		# oFrequency= plaintext[x].count('o') / float(len (plaintext[x]))
		# spaceFrequency = plaintext[x].count(' ') / float(len(plaintext[x]))

		# Dervie a score based on most common letter frequencies
			# score is distance from most common letter frequencies
		# scores.append (abs(eFrequency - .12702) + abs(tFrequency - .09056) + abs(aFrequency - .08167) + abs(oFrequency - .12507) + abs(spaceFrequency - .17647))
		

	# return item with highest score
	idx = max(enumerate(scores), key=itemgetter(1))[0] + 32
	return (plaintext[idx-32],  scores[idx-32], str(unichr(idx)))
	

## 4 Detect single-character XOR ##
def detectSCX():
	lines = [base64.b16decode(line.strip().upper()) for line in open('4.txt')]

	plaintexts = []
	scores = []

	for x in lines:
		tmp = SBXdecipher(x)
		plaintexts.append (tmp[0])
		scores.append (tmp[1])

	return plaintexts[max(enumerate(scores), key=itemgetter(1))[0]]


## 5 implement repeating-key XOR ##

def RKXencrypt():
	plainText="Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	key = "ICE"
	cipherText = ""

	for x in range(0,len(plainText)):
		cipherText += base64.b16encode(XOR.XORCipher.encrypt(XOR.new(key[x % 3]), plainText[x]))

	print cipherText

	if cipherText == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f".upper():
		print "Test Passed"


## 6 Break repeating-key XOR ##

def hamming(str1, str2):
	# XOR the two hex strings and then count the number of 1's
	return bin(int(str1, 16) ^ int(str2, 16)).count("1")

def RKXdecrypt(byte, key):
	# XOR a byte and its key
	return unichr(int(byte, 16) ^ ord(key))
		
def breakRKX():
	bytes = []
	# str1 = "this is a test"
	# str2 = "wokka wokka!!!"
	# print hamming(base64.b16encode(str1),base64.b16encode(str2))

	## INTAKE CIPHERTEXT

	# Open file and read contents into single buffer and encode to Hex for easy byte grabbing
	with open('7.txt') as f:
	    data =''.join(base64.b16encode(base64.b64decode(line.strip())) for line in f)

	# data = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f".upper()
	
	# Split data into bytes
	for i in range(0,len(data),2):
		bytes.append (data[i:i+2])

	## FIND KEYSIZE
	scores = []

	for KEYSIZE in range(2,15):
		
		# currentDist = []

		# # number of different hammings to calculate and average
		# hammingRounds = 4

		# # Take two KEYSIZE worth of bytes and find hamming distance between them
		# for n in range(1,hammingRounds,KEYSIZE):
		# 	b1 = ""
		# 	b2 = ""

		# 	for i in range(n-1,n*KEYSIZE):
		# 		b1 += bytes[i]

		# 	for j in range(n*KEYSIZE,2*n*KEYSIZE):
		# 		b2 += bytes[j]

		# 	currentDist.append(hamming(b1,b2) / float(KEYSIZE))

		# # Find the average for the 4 hamming distances
		# sSum = 0
		# for e in currentDist:
		# 	sSum += e
		# avgHam = sSum / hammingRounds
		# scores.append((avgHam,KEYSIZE))

		#Take the first and second KEYSIZE worth of bytes and find the hamming distance
		tmpScore1 = hamming(''.join(bytes[0:KEYSIZE]), ''.join(bytes[KEYSIZE:2*KEYSIZE])) / float(KEYSIZE)
		tmpScore2 = hamming(''.join(bytes[2*KEYSIZE:3*KEYSIZE]), ''.join(bytes[3*KEYSIZE:4*KEYSIZE])) / float(KEYSIZE)
		tmpScoreAvg = (tmpScore1 + tmpScore2) / 2
		scores.append((tmpScoreAvg, KEYSIZE))
		

	
	# Find the KEYSIZE w/ the smallest edit distance and set it to KEYSIZE
	scores.sort(key=lambda tup: tup[0])
	KEYSIZE = scores[0][1]
	print KEYSIZE

	## FIND KEY
	# Split the data into chunks where C1 contains the 1st byte from Block1 to BlockN, 
	# 	and C2 contaions the 2nd byte from Block1 to BlockN, and so forth
	chunks = []
	for j in range(0,KEYSIZE+2,2):
		chunkTmp = ""
		for i in range(0,len(data),KEYSIZE*2):
			chunkTmp += base64.b16decode(data[i:i+KEYSIZE*2][j:j+2])
		chunks.append(base64.b16encode(chunkTmp))

	# Take the most likely key for each Chunck and assemble it to a KEY
	key = ""
	for chunk in chunks:
		key += SBXdecipher(base64.b16decode(chunk))[2]


	## DECRYPT

	# Take each byte and decrypt with key
	plaintext = ""
	for i in range(0,len(bytes)):
		plaintext += RKXdecrypt(bytes[i],key[i % len(key)])
	 
	print "Key:", key
	print "Plain Text:\n",plaintext


## 7 AES in ECB mode ##
def AESinECBdecrypt(key,data):
	
	# Set up AES 
	mode = AES.MODE_ECB
	cipher = AES.new(key, mode)

	# Decrypt data
	return cipher.decrypt(data)

def AESinECBencrypt(key,data):
	
	# Set up AES 
	mode = AES.MODE_ECB
	cipher = AES.new(key, mode)

	# encrypt data
	return cipher.encrypt(data)

## 8 Detect AES in ECB mode ##

def detectECB():
	# Open file 
	lines = [base64.b16decode(line.strip().upper()) for line in open('8.txt')]

	scores = []
	for line in lines:
		scores.append (FrequencyFinder.getEnglishDistance(line))

	idx = min(enumerate(scores), key=itemgetter(1))[0]
	print "line", idx,"is most likely in ECB based on character frequency"
	print "Line", idx,": ", base64.b16encode(lines[idx])
	




if __name__ =='__main__':

	print "## 1 Convert to base64 and back ##\n"
	print util.b16tob64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")

	print "\n\n## 2 Fixed XOR ##\n"
	print xor(base64.b16decode("AAAA".upper()), base64.b16decode("BBBB".upper()))

	print "\n\n## 3 Single-byte XOR Cipher ##\n"
	print SBXdecipher(util.b16decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".upper()))[0]

	print "\n\n## 4 Detect single-character XOR ##\n"
	print detectSCX

	print "\n\n## 5 implement repeating-key XOR ##\n"
	print RKXencrypt()

	print "\n\n## 6 Break repeating-key XOR ##\n"
	print breakRKX()

	print "\n\n## 7 AES in ECB mode ##\n"
	key = "YELLOW SUBMARINE"

	# Open file and read contents into single buffer
	with open('7.txt') as f:
	    data=''.join(util.b64decode(line.strip()) for line in f)
	
	print AESinECBdecrypt(key,data)

	print "\n\n## 8 Detect AES in ECB mode ##\n"
	print detectECB()