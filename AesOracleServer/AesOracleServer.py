import base64
import hashlib
import time
from bottle import route, run, template
from Crypto.Cipher import AES
from Crypto import Cipher
from Crypto.Util.Padding import unpad

def fromWeb64(s):
    s = s.replace('~','=').replace('-','+').replace('!','/')
    b = base64.b64decode(s)
    return b

def toWeb64(b):
    return str(base64.b64encode(b),'ascii').replace('=','~').replace('+','-').replace('/','!')

def pkcs_pad(s):
    ret = s[:]
    pad = len(ret) % 16
    pad = 16 - pad
    padbuf = bytes([pad]*pad)
    return ret + padbuf

def pkcs_unpad(b):
    padding = b[-1]
    b = b[ : -padding]
    return b

@route('/hello/<name>')
def index(name):
    return template('<b>Hello {{name}}</b>!', name=name)

@route('/payload/<enc>')
def index(enc):
    try:
        raw = fromWeb64(enc)
        IV = raw[ : 16]
        CT = raw[16 : ]
        res = AES.new(b"SuperSecretSauce", AES.MODE_CBC, IV ).decrypt(CT)
        res = unpad(res, 16, 'pkcs7')
        return template('<b>Plain: {{res}}</b>', res=res)
    except Exception as ex:
        return repr(ex.args)

@route('/example')
def index():
    m = hashlib.md5()
    m.update(repr(time.time()).encode('ascii'))
    IV = m.digest()[ :16]
    res = toWeb64(IV + AES.new(b'SuperSecretSauce', AES.MODE_CBC, IV).encrypt(pkcs_pad(b'{ "example" : "json" }')))
    return template('<b>Example: {{res}}</b>', res=res)

run(host='localhost', port=8080)