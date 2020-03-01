
# https://en.wikipedia.org/wiki/RC4

class NaiveRC4(object):
    def __init__(self, key=None):
        self._s = range(256)
        self._i = 0
        self._j = 0
        if key: self.prepare(key)
        
    def prepare(self, key):
        self.KSA(key)
        #throw away first 3000 bytes
        for i in range(3000):
            _ = self.process(['\x00'])

    def encrypt(self, data):
        res = self.process(data)
        return "".join(['%02X' % x for x in res])

    def decrypt(self, data):
        tmp = [int('0x'+data[i:i+2], 16) for i in range(0, len(data), 2)]
        res = self.process(tmp)
        return "".join ([chr(x) for x in res])

    def process(self, data):
        res = []
        for x in data:
            decoded = ''
            if isinstance(x, int):
                decoded = x ^ self.PRGA()
            else:
                decoded = ord(x) ^ self.PRGA()
            res.append(decoded)
        return res        

    def KSA(self, key):
        for i in range(256): self._s[i] = i
        j = 0
        keysize = len(key)
        if isinstance(key, basestring):
            key = self.str2byte(key)
        for i in range(256):
            j = (j + self._s[i] + key[i % keysize]) % 256
            self._s[i], self._s[j] = self._s[j], self._s[i]

    def PRGA(self):
        self._i = (self._i + 1) % 256
        self._j = (self._j + self._s[self._i]) % 256
        self._s[self._i], self._s[self._j] = self._s[self._j], self._s[self._i]
        res = self._s[(self._s[self._i] + self._s[self._j]) % 256]
        return res

    def str2byte(self, string):
        res = [ord (x) for x in string]
        return res

    def byte2str(self, string):
        res = [chr (x) for x in string]
        return res
    

if __name__ == '__main__':
    s = NaiveRC4()
    # examples from https://sourceforge.net/p/tinycrypt/svn/HEAD/tree/testARC4.c
    key = 'Key'
    s.prepare(s.str2byte(key))
    plaintext = 'Plaintext'
    
    # ciphertext should be BBF316E8D940AF0AD3
    expected=s.encrypt(plaintext)
    print 'Output is expected to be 452760F1FA169D8A10. It is:' + expected

    d1 = NaiveRC4(key)
    assert plaintext == d1.decrypt(expected)

    s = NaiveRC4('Wiki')
    assert s.encrypt('pedia') == 'D01C2F50CD' # or '1021BF0420' when not skipping firs 3000 bytes

    s = NaiveRC4('Secret')
    assert s.encrypt('Attack at dawn') == '796DB9175E2F7BA3D812AA506A84' # or '45A01F645FC35B383552544B9BF5' when skipping
    
