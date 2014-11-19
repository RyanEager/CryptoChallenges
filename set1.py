# Using PyCrypto from: https://www.dlitz.net/software/pycrypto/
from Crypto.Cipher import XOR, AES
from operator import itemgetter
from collections import Counter
import util, sys, base64


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
	for key in range(32,127):
		# XOR cipherText against ascii chars
		plaintext.append(util.xor(str(unichr(key)), cipherText))
		scores.append(letterFrequency(plaintext[key-32]))


	# return item with highest score
	idx = min(enumerate(scores), key=itemgetter(1))[0] + 32
	# returns (plaintext, score, key)
	return (plaintext[idx-32],  scores[idx-32], str(unichr(idx)))
	
# frequencys from http://reusablesec.blogspot.com/2009/05/character-frequency-analysis-info.html
englishLetterFreq = {'a' : 7.52766,'e' : 7.0925,'o' : 5.17,'r' : 4.96032,'i' : 4.69732,'s' : 4.61079,'n' : 4.56899,'1' : 4.35053,'t' : 3.87388,'l' : 3.77728,'2' : 3.12312,'m' : 2.99913,'d' : 2.76401,'0' : 2.74381,'c' : 2.57276,'p' : 2.45578,'3' : 2.43339,'h' : 2.41319,'b' : 2.29145,'u' : 2.10191,'k' : 1.96828,'4' : 1.94265,'5' : 1.88577,'g' : 1.85331,'9' : 1.79558,'6' : 1.75647,'8' : 1.66225,'7' : 1.621,'y' : 1.52483,'f' : 1.2476,'w' : 1.24492,'j' : 0.836677,'v' : 0.833626,'z' : 0.632558,'x' : 0.573305,'q' : 0.346119,'A' : 0.130466,'S' : 0.108132,'E' : 0.0970865,'R' : 0.08476,'B' : 0.0806715,'T' : 0.0801223,'M' : 0.0782306,'L' : 0.0775594,'N' : 0.0748134,'P' : 0.073715,'O' : 0.0729217,'I' : 0.070908,'D' : 0.0698096,'C' : 0.0660872,'H' : 0.0544319,'G' : 0.0497332,'K' : 0.0460719,'F' : 0.0417393,'J' : 0.0363083,'U' : 0.0350268,'W' : 0.0320367,'.' : 0.0316706,'!' : 0.0306942,'Y' : 0.0255073,'*' : 0.0241648,'@' : 0.0238597,'V' : 0.0235546,'-' : 0.0197712,'Z' : 0.0170252,'Q' : 0.0147064,'X' : 0.0142182,'_' : 0.0122655,'$' : 0.00970255,'#' : 0.00854313,',' : 0.00323418,'/' : 0.00311214,'+' : 0.00231885,'?' : 0.00207476,';' : 0.00207476,'^' : 0.00195272,' ' : 0.00189169,'%' : 0.00170863,'~' : 0.00152556,'=' : 0.00140351,'&' : 0.00134249,'`' : 0.00115942,'\\' : 0.00115942,')' : 0.00115942,']' : 0.0010984,'[' : 0.0010984,':' : 0.000549201,'<' : 0.000427156,'(' : 0.000427156,'>' : 0.000183067,'"' : 0.000122045,'|' : 0.000122045,'{' : 0.000122045,'\'' : 0.000122045,'}' : 6.10223e-0}
# {' ':13.0, 'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97, 'N': 6.75, 'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25, 'L': 4.03, 'C': 2.78, 'U': 2.76, 'M': 2.41, 'W': 2.36, 'F': 2.23, 'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.29, 'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15, 'Q': 0.10, 'Z': 0.07,'!' : 0,'"' : 0,'&' : 0,'\'' : 0,',' : 0,'-' : 0,'.' : 0,'0' : 0,'1' : 0,'2' : 0,'3' : 0,'4' : 0,'5' : 0,'6' : 0,'7' : 0,'8' : 0,'9' : 0,':' : 0,';' : 0,'?': 0, '\n': 0, '\t' : 0, '\r': 0} 

def letterFrequency(message):
	length = len(message)
	letterCount = Counter(message)
	freq = {}
	score = 0

	for (k,v) in letterCount.items():

		if k not in englishLetterFreq:
			englishLetterFreq[k] = 0
		
		freq[k] = (v / float(length)) * 100 

	for (k,v) in freq.items():
		score += abs(freq[k] - englishLetterFreq[k])


	return score


## 4 Detect single-character XOR ##
def detectSCX():
	lines = [util.b16decode(line.strip().upper()) for line in open('4.txt')]

	plaintexts = []
	scores = []

	for line in lines:
		tmp = SBXdecipher(line)
		plaintexts.append (tmp[0])
		scores.append (tmp[1])

	return plaintexts[min(enumerate(scores), key=itemgetter(1))[0]]


## 5 implement repeating-key XOR ##

def RKXencrypt():
	plainText="Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	key = "ICE"
	cipherText = ""

	for x in range(0,len(plainText)):
		cipherText += util.b16encode(XOR.XORCipher.encrypt(XOR.new(key[x % 3]), plainText[x]))

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
	str1 = "this is a test"
	str2 = "wokka wokka!!!"
	print "Should be 37:", hamming(util.b16encode(str1),util.b16encode(str2))

	## INTAKE CIPHERTEXT

	# Open file and read contents into single buffer and encode to Hex for easy byte grabbing
	with open('6.txt') as f:
	    data =''.join(util.b64tob16(line.strip()) for line in f)

	# Split data into bytes
	for i in range(0,len(data),2):
		bytes.append (data[i:i+2])

	## FIND KEYSIZE
	scores = []

	for KEYSIZE in range(2,40):

		#Take the first and second KEYSIZE worth of bytes and find the hamming distance
		tmpScore1 = hamming(''.join(bytes[0:KEYSIZE]), ''.join(bytes[KEYSIZE:2*KEYSIZE])) / float(KEYSIZE)
		tmpScore2 = hamming(''.join(bytes[2*KEYSIZE:3*KEYSIZE]), ''.join(bytes[3*KEYSIZE:4*KEYSIZE])) / float(KEYSIZE)
		tmpScoreAvg = (tmpScore1 + tmpScore2) / 2
		scores.append((tmpScoreAvg, KEYSIZE))
		
	# Find the KEYSIZE w/ the smallest edit distance and set it to KEYSIZE
	print scores
	scores.sort(key=lambda tup: tup[0])
	KEYSIZE = scores[0][1]

	## FIND KEY
	# Split the data into chunks where C1 contains the 1st byte from Block1 to BlockN, 
	# 	and C2 contaions the 2nd byte from Block1 to BlockN, and so forth
	chunks = []
	for j in range(0,KEYSIZE+2,2):
		chunkTmp = ""
		for i in range(0,len(data),KEYSIZE*2):
			chunkTmp += util.b16decode(data[i:i+KEYSIZE*2][j:j+2])
		chunks.append(util.b16encode(chunkTmp))

	# Take the most likely key for each Chunck and assemble it to a KEY
	key = ""
	for chunk in chunks:
		key += SBXdecipher(util.b16decode(chunk))[2]


	## DECRYPT

	# Take each byte and decrypt with key
	plaintext = ""
	for byte in range(0,len(bytes)):
		plaintext += RKXdecrypt(bytes[byte],key[byte % len(key)])
	 
	print "Key:", key
	# print "Plain Text:\n",plaintext


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
	lines = [util.b16decode(line.strip().upper()) for line in open('8.txt')]

	scores = []
	for line in lines:
		scores.append (FrequencyFinder.getEnglishDistance(line))

	idx = min(enumerate(scores), key=itemgetter(1))[0]
	print "line", idx,"is most likely in ECB based on character frequency"
	print "Line", idx,": ", util.b16encode(lines[idx])
	




if __name__ =='__main__':

	# print "## 1 Convert to base64 and back ##\n"
	# print util.b16tob64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")

	# print "\n\n## 2 Fixed XOR ##\n"
	# print xor(util.b16decode("AAAA".upper()), util.b16decode("BBBB".upper()))

	# print "\n\n## 3 Single-byte XOR Cipher ##\n"
	# print SBXdecipher(util.b16decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".upper()))[0]

	# print "\n\n## 4 Detect single-character XOR ##\n"
	# print detectSCX()

	# print "\n\n## 5 implement repeating-key XOR ##\n"
	# RKXencrypt()

	print "\n\n## 6 Break repeating-key XOR ##\n"
	breakRKX()

	# print "\n\n## 7 AES in ECB mode ##\n"
	# key = "YELLOW SUBMARINE"

	# # Open file and read contents into single buffer
	# with open('7.txt') as f:
	#     data=''.join(util.b64decode(line.strip()) for line in f)
	
	# print AESinECBdecrypt(key,data)

	# print "\n\n## 8 Detect AES in ECB mode ##\n"
	# print detectECB()