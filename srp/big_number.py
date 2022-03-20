import ctypes
import ctypes.util
import sys
import os

dlls = list()

platform = sys.platform
if platform == "darwin":
    dlls.append(ctypes.cdll.LoadLibrary("libssl.32.dylib"))
elif "win" in platform:
    for d in ("libcrypto-1_1-x64.dll",):
        try:
            dlls.append(ctypes.cdll.LoadLibrary(d))
        except:
            pass
else:
    try:
        dlls.append(ctypes.cdll.LoadLibrary("libssl.so.1.1.0"))
    except OSError:
        dlls.append(ctypes.cdll.LoadLibrary("libssl.so"))


class BIGNUM_Struct(ctypes.Structure):
    _fields_ = [
        ("d", ctypes.c_void_p),
        ("top", ctypes.c_int),
        ("dmax", ctypes.c_int),
        ("neg", ctypes.c_int),
        ("flags", ctypes.c_int),
    ]


BIGNUM = ctypes.POINTER(BIGNUM_Struct)


class BN_CTX_Struct(ctypes.Structure):
    _fields_ = [("_", ctypes.c_byte)]


BN_CTX = ctypes.POINTER(BN_CTX_Struct)


def load_func(name, args, returns=ctypes.c_int):
    d = sys.modules[__name__].__dict__
    f = None

    for dll in dlls:
        try:
            f = getattr(dll, name)
            f.argtypes = args
            f.restype = returns
            d[name] = f
            return
        except:
            pass
    raise ImportError("Unable to load required functions from SSL dlls")


load_func("BN_new", [], BIGNUM)
load_func("BN_free", [BIGNUM], None)

load_func("BN_CTX_new", [], BN_CTX)
load_func("BN_CTX_free", [BN_CTX], None)

load_func("BN_set_flags", [BIGNUM, ctypes.c_int], None)
BN_FLG_CONSTTIME = 0x04

# load_func("BN_cmp", [BIGNUM, BIGNUM], ctypes.c_int)

load_func("BN_num_bits", [BIGNUM], ctypes.c_int)

load_func("BN_add", [BIGNUM, BIGNUM, BIGNUM])
load_func("BN_sub", [BIGNUM, BIGNUM, BIGNUM])
load_func("BN_mul", [BIGNUM, BIGNUM, BIGNUM, BN_CTX])
load_func("BN_div", [BIGNUM, BIGNUM, BIGNUM, BIGNUM, BN_CTX])
load_func("BN_mod_exp", [BIGNUM, BIGNUM, BIGNUM, BIGNUM, BN_CTX])
load_func("BN_is_zero", [BIGNUM], ctypes.c_int)

load_func("BN_rand", [BIGNUM, ctypes.c_int, ctypes.c_int, ctypes.c_int])

load_func("BN_bn2bin", [BIGNUM, ctypes.c_char_p])
load_func("BN_bin2bn", [ctypes.c_char_p, ctypes.c_int, BIGNUM], BIGNUM)

load_func("BN_hex2bn", [ctypes.POINTER(BIGNUM), ctypes.c_char_p])

load_func("RAND_seed", [ctypes.c_char_p, ctypes.c_int])


# ---------------------------------------------------------
# Init
#
RAND_seed(os.urandom(32), 32)


class BigNumberCtx:
    def __init__(self):
        self._ctx: BN_CTX = BN_CTX_new()

    def __del__(self):
        if not hasattr(self, "_ctx"):
            return
        BN_CTX_free(self._ctx)


class BigNumber:
    def __init__(
        self, *, hexstr: bytes = None, srcbytes: bytes = None, ctx: BigNumberCtx = None
    ):
        self._bn: BIGNUM = BN_new()

        assert not (hexstr and srcbytes), "Cannot set both from hex and from raw bytes"
        if hexstr:
            BN_hex2bn(self._bn, hexstr)
        if srcbytes:
            BN_bin2bn(srcbytes, len(srcbytes), self._bn)

        self._ctx = ctx

    def __del__(self):
        if not hasattr(self, "_bn"):
            return
        BN_free(self._bn)

    def num_bits(self) -> int:
        return BN_num_bits(self._bn)

    def num_bytes(self) -> int:
        return (self.num_bits() + 7) // 8

    def to_bytes(self) -> bytes:
        buffer = ctypes.create_string_buffer(self.num_bytes())
        BN_bn2bin(self._bn, buffer)
        return buffer.raw

    def is_zero(self) -> bool:
        return BN_is_zero(self._bn) == 1

    def _set_flag(self, flag):
        BN_set_flags(self._bn, flag)

    def consttime(self):
        self._set_flag(BN_FLG_CONSTTIME)

    def __mod__(self, other: "BigNumber") -> "BigNumber":
        # TODO asssert type of other
        result = BigNumber(ctx=self._ctx)

        ctx = self._ctx or other._ctx
        if not ctx:
            self._ctx = BigNumberCtx()
            ctx = self._ctx

        BN_div(None, result._bn, self._bn, other._bn, ctx._ctx)
        return result

    def __mul__(self, other: "BigNumber") -> "BigNumber":
        # TODO asssert type of other
        result = BigNumber(ctx=self._ctx)

        ctx = self._ctx or other._ctx
        if not ctx:
            self._ctx = BigNumberCtx()
            ctx = self._ctx

        BN_mul(result._bn, self._bn, other._bn, ctx._ctx)
        return result

    def __pow__(self, other: "BigNumber", modulo: "BigNumber" = None) -> "BigNumber":
        # TODO asssert type of other
        if not modulo:
            raise NotImplementedError()

        result = BigNumber(ctx=self._ctx)

        ctx = self._ctx or other._ctx or modulo._ctx
        if not ctx:
            self._ctx = BigNumberCtx()
            ctx = self._ctx

        BN_mod_exp(result._bn, self._bn, other._bn, modulo._bn, ctx._ctx)
        return result

    def __add__(self, other: "BigNumber") -> "BigNumber":
        # TODO asssert type of other
        result = BigNumber(ctx=self._ctx)
        BN_add(result._bn, self._bn, other._bn)
        return result

    def __sub__(self, other: "BigNumber") -> "BigNumber":
        # TODO asssert type of other
        result = BigNumber(ctx=self._ctx)
        BN_sub(result._bn, self._bn, other._bn)
        return result

    @staticmethod
    def rand(bits, top, bottom, ctx=None) -> "BigNumber":
        result = BigNumber(ctx=ctx)
        BN_rand(result._bn, bits, top, bottom)
        return result
