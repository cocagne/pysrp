  # N    A large safe prime (N = 2q+1, where q is prime)
  #      All arithmetic is done modulo N.
  # g    A generator modulo N
  # k    Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
  # s    User's salt
  # I    Username
  # p    Cleartext Password
  # H()  One-way hash function
  # ^    (Modular) Exponentiation
  # u    Random scrambling parameter
  # a,b  Secret ephemeral values
  # A,B  Public ephemeral values
  # x    Private key (derived from p and s)
  # v    Password verifier

from __future__ import division
import os
import sys
import hashlib
import ctypes
import time
import six
from .big_number import BigNumber, BigNumberCtx


_rfc5054_compat = False
_no_username_in_x = False

def rfc5054_enable(enable=True):
    global _rfc5054_compat
    _rfc5054_compat = enable

def no_username_in_x(enable=True):
    global _no_username_in_x
    _no_username_in_x = enable


SHA1   = 0
SHA224 = 1
SHA256 = 2
SHA384 = 3
SHA512 = 4

NG_1024   = 0
NG_2048   = 1
NG_4096   = 2
NG_8192   = 3
NG_CUSTOM = 4

_hash_map = { SHA1   : hashlib.sha1,
              SHA224 : hashlib.sha224,
              SHA256 : hashlib.sha256,
              SHA384 : hashlib.sha384,
              SHA512 : hashlib.sha512 }


_ng_const = (
# 1024-bit
(six.b('''\
EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496\
EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8E\
F4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA\
9AFD5138FE8376435B9FC61D2FC0EB06E3'''),
six.b("2")),
# 2048
(six.b('''\
AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4\
A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF60\
95179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF\
747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B907\
8717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861\
60279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DB\
FBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73'''),
six.b("2")),
# 4096
(six.b('''\
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08\
8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B\
302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9\
A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6\
49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8\
FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D\
670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C\
180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718\
3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D\
04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D\
B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226\
1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C\
BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC\
E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26\
99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB\
04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2\
233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127\
D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199\
FFFFFFFFFFFFFFFF'''),
six.b("5")),
# 8192
(six.b('''\
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08\
8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B\
302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9\
A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6\
49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8\
FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D\
670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C\
180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718\
3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D\
04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D\
B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226\
1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C\
BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC\
E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26\
99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB\
04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2\
233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127\
D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492\
36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406\
AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918\
DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B33205151\
2BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03\
F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97F\
BEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA\
CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58B\
B7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632\
387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E\
6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA\
3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C\
5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD9\
22222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC886\
2F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A6\
6D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC5\
0846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268\
359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6\
FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E71\
60C980DD98EDD3DFFFFFFFFFFFFFFFFF'''),
six.b('13'))
)



#N_HEX  = "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"
#G_HEX  = "2"
#HNxorg = None



def bytes_to_bn( dest_bn, bytes ):
    BN_bin2bn(bytes, len(bytes), dest_bn)


def H_str( hash_class, dest_bn, s ):
    d = hash_class(s).digest()
    buff = ctypes.create_string_buffer( s )
    BN_bin2bn(d, len(d), dest)


def H_bn( hash_class, dest, n ):
    bin = ctypes.create_string_buffer( BN_num_bytes(n) )
    BN_bn2bin(n, bin)
    d = hash_class( bin.raw ).digest()
    BN_bin2bn(d, len(d), dest)


def H_bn_bn( hash_class, n1: BigNumber, n2 : BigNumber, width ) -> BigNumber:
    h    = hash_class()
    bin1 = n1.to_bytes()
    bin2 = n2.to_bytes()
    if _rfc5054_compat:
        h.update(bytes(width - len(bin1)))
    h.update( bin1 )
    if _rfc5054_compat:
        h.update(bytes(width - len(bin2)))
    h.update( bin2 )
    return BigNumber(hexstr=h.hexdigest().encode())


def H_bn_str( hash_class, n, s):
    h   = hash_class()
    bin = n.to_bytes()
    h.update(bin)
    h.update(s)
    return BigNumber(hexstr=h.hexdigest().encode())

def calculate_x(hash_class, salt, username, password ):
    username = username.encode() if hasattr(username, 'encode') else username
    password = password.encode() if hasattr(password, 'encode') else password
    if _no_username_in_x:
        username = six.b('')
    up = hash_class(username + six.b(':') + password).digest()
    x = H_bn_str( hash_class, salt, up)
    x.consttime()
    return x


def calculate_M( hash_class, N, g, I, s, A, B, K ):
    I = I.encode() if hasattr(I, 'encode') else I
    h = hash_class()
    h.update( HNxorg( hash_class, N, g ) )
    h.update( hash_class(I).digest() )
    h.update(s.to_bytes())
    h.update(A.to_bytes())
    h.update(B.to_bytes())
    h.update( K )
    return h.digest()


def calculate_H_AMK( hash_class, A, M, K ):
    h = hash_class()
    h.update(A.to_bytes())
    h.update( M )
    h.update( K )
    return h.digest()


def HNxorg( hash_class, N, g ):
    bN = N.to_bytes()
    bg = g.to_bytes()

    padding = len(bN) - len(bg) if _rfc5054_compat else 0

    hN = hash_class( bN ).digest()
    hg = hash_class( b''.join([ b'\0'*padding, bg ]) ).digest()

    return six.b( ''.join( chr( six.indexbytes(hN, i) ^ six.indexbytes(hg, i) ) for i in range(0,len(hN)) ) )


def get_ngk( hash_class, ng_type, n_hex, g_hex, ctx ):
    if ng_type < NG_CUSTOM:
        n_hex, g_hex = _ng_const[ ng_type ]
    N = BigNumber(hexstr = n_hex, ctx=ctx)
    g = BigNumber(hexstr = g_hex, ctx=ctx)
    k = BigNumber(ctx=ctx)

    k = H_bn_bn(hash_class, N, g, width=N.num_bytes())
    if _rfc5054_compat:
        k = k % N
    return N, g, k



def create_salted_verification_key( username, password, hash_alg=SHA1, ng_type=NG_2048, n_hex=None, g_hex=None, salt_len=4 ):
    if ng_type == NG_CUSTOM and (n_hex is None or g_hex is None):
        raise ValueError("Both n_hex and g_hex are required when ng_type = NG_CUSTOM")
    
    ctx  = BigNumberCtx()

    hash_class = _hash_map[ hash_alg ]
    N,g,k      = get_ngk( hash_class, ng_type, n_hex, g_hex, ctx )

    s = BigNumber.rand(salt_len * 8, -1, 0, ctx=ctx)
    x = calculate_x( hash_class, s, username, password )
    v = pow(g, x, N)

    salt     = s.to_bytes()
    verifier = v.to_bytes()

    return salt, verifier



class Verifier (object):
    def __init__(self,  username, bytes_s, bytes_v, bytes_A, hash_alg=SHA1, ng_type=NG_2048, n_hex=None, g_hex=None, bytes_b=None):
        if ng_type == NG_CUSTOM and (n_hex is None or g_hex is None):
            raise ValueError("Both n_hex and g_hex are required when ng_type = NG_CUSTOM")
        if bytes_b and len(bytes_b) != 32:
            raise ValueError("32 bytes required for bytes_b")

        self._authenticated = False
        self.safety_failed = False
        self.ctx   = BigNumberCtx()
        self.I     = username
        self.b     = BigNumber(ctx=self.ctx)
        self.s     = BigNumber(srcbytes = bytes_s, ctx=self.ctx)
        self.B     = BigNumber(ctx=self.ctx)
        self.K     = None
        self.M     = None
        self.H_AMK = None



        hash_class = _hash_map[ hash_alg ]
        N,g,k      = get_ngk( hash_class, ng_type, n_hex, g_hex, self.ctx )

        self.hash_class = hash_class
        self.N          = N
        self.g          = g
        self.k          = k

        A     = BigNumber(srcbytes = bytes_A, ctx=self.ctx)
        # SRP-6a safety check
        tmp1 = A % N
        if tmp1.is_zero():
            self.safety_failed = True
        else:
            if bytes_b:
                self.b = BigNumber(srcbytes=bytes_b, ctx=self.ctx)
            else:
                self.b = BigNumber.rand(256, 0, 0, ctx=self.ctx)
            self.b.consttime()

            # B = kv + g^b
            v    = BigNumber(srcbytes = bytes_v, ctx=self.ctx)
            tmp1 = self.k * v
            tmp2 = pow(g, self.b, N)
            self.B = tmp1 + tmp2
            self.B = self.B % N

            u = H_bn_bn(hash_class, A, self.B, width=N.num_bytes())

            # S = (A *(v^u)) ^ b
            tmp1 = pow(v, u, N)
            tmp2 = A * tmp1
            S = pow(tmp2, self.b, N)

            self.K = hash_class(S.to_bytes()).digest()

            self.M     = calculate_M( hash_class, N, g, self.I, self.s, A, self.B, self.K )
            self.H_AMK = calculate_H_AMK( hash_class, A, self.M, self.K )


    def authenticated(self):
        return self._authenticated


    def get_username(self):
        return self.I


    def get_ephemeral_secret(self):
        return self.b.to_bytes()


    def get_session_key(self):
        return self.K if self._authenticated else None


    # returns (bytes_s, bytes_B) on success, (None,None) if SRP-6a safety check fails
    def get_challenge(self):
        if self.safety_failed:
            return None, None
        else:
            return self.s.to_bytes(), self.B.to_bytes()


    def verify_session(self, user_M):
        if user_M == self.M:
            self._authenticated = True
            return self.H_AMK




class User (object):
    def __init__(self, username, password, hash_alg=SHA1, ng_type=NG_2048, n_hex=None, g_hex=None, bytes_a=None, bytes_A=None):
        if ng_type == NG_CUSTOM and (n_hex is None or g_hex is None):
            raise ValueError("Both n_hex and g_hex are required when ng_type = NG_CUSTOM")
        if bytes_a and len(bytes_a) != 32:
            raise ValueError("32 bytes required for bytes_a")
        self.username = username
        self.password = password
        self.ctx   = BigNumberCtx()
        self.a     = BigNumber(ctx=self.ctx)
        self.A     = BigNumber(ctx=self.ctx)
        self.B     = BigNumber(ctx=self.ctx)
        self.s     = BigNumber(ctx=self.ctx)
        self.S     = BigNumber(ctx=self.ctx)
        self.u     = BigNumber(ctx=self.ctx)
        self.x     = BigNumber(ctx=self.ctx)
        self.v     = BigNumber(ctx=self.ctx)
        self.tmp1  = BigNumber(ctx=self.ctx)
        self.tmp2  = BigNumber(ctx=self.ctx)
        self.tmp3  = BigNumber(ctx=self.ctx)
        self.M     = None
        self.K     = None
        self.H_AMK = None
        self._authenticated = False

        hash_class = _hash_map[ hash_alg ]
        N,g,k      = get_ngk( hash_class, ng_type, n_hex, g_hex, self.ctx )

        self.hash_class = hash_class
        self.N          = N
        self.g          = g
        self.k          = k

        if bytes_a:
            self.a = BigNumber(srcbytes=bytes_a, ctx=self.ctx)
        else:
            self.a = BigNumber.rand(256, 0, 0, ctx=self.ctx)

        if bytes_A:
            self.A = BigNumber(srcbytes=bytes_A, ctx=self.ctx)
        else:
            self.a.consttime()
            self.A = pow(g, self.a, N)


    def authenticated(self):
        return self._authenticated


    def get_username(self):
        return self.username


    def get_ephemeral_secret(self):
        return self.a.to_bytes()


    def get_session_key(self):
        return self.K if self._authenticated else None


    def start_authentication(self):
        return (self.username, self.A.to_bytes())


    # Returns M or None if SRP-6a safety check is violated
    def process_challenge(self, bytes_s, bytes_B):

        hash_class = self.hash_class
        N = self.N
        g = self.g
        k = self.k

        self.s = BigNumber(srcbytes=bytes_s, ctx=self.ctx)
        self.B = BigNumber(srcbytes=bytes_B, ctx=self.ctx)

        # SRP-6a safety check
        if self.B.is_zero():
            return None

        self.u = H_bn_bn(hash_class, self.A, self.B, width=N.num_bytes)

        # SRP-6a safety check
        if self.u.is_zero():
            return None

        self.x = calculate_x( hash_class, self.s, self.username, self.password )
        self.v = pow(g, self.x, self.N)

        # S = (B - k*(g^x)) ^ (a + ux)

        tmp1 = self.u * self.x
        tmp2 = self.a + tmp1
        tmp1 = pow(g, self.x, N)
        tmp3 = k * tmp1
        tmp1 = self.B - tmp3
        self.S = pow(tmp1, tmp2, N)

        self.K     = hash_class(self.S.to_bytes()).digest()
        self.M     = calculate_M( hash_class, N, g, self.username, self.s, self.A, self.B, self.K )
        self.H_AMK = calculate_H_AMK( hash_class, self.A, self.M, self.K )

        return self.M


    def verify_session(self, host_HAMK):
        if self.H_AMK == host_HAMK:
            self._authenticated = True

