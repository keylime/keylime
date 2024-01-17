# pylint: disable=protected-access

from typing import Any, Optional

from cryptography.hazmat.bindings.openssl import binding
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey


class EcCryptoHelper:
    instance: Optional["EcCryptoHelper"] = None

    @staticmethod
    def get_instance() -> "EcCryptoHelper":
        """Create and return a singleton EcCryptoHelper"""
        if not EcCryptoHelper.instance:
            EcCryptoHelper.instance = EcCryptoHelper()
        return EcCryptoHelper.instance

    def __init__(self) -> None:
        self.binding = binding.Binding()
        lib = self.binding.lib
        assert lib

        for func in [
            "BN_CTX_end",
            "BN_CTX_free",
            "BN_CTX_get",
            "BN_CTX_new",
            "BN_CTX_start",
            "BN_free",
            "EC_KEY_get0_group",
            "EC_POINT_new",
            "EC_POINT_free",
            "EC_POINT_mul",
        ]:
            if not hasattr(lib, func):
                raise Exception(f"{func} not available in lib {str(dir(lib))}")

        if hasattr(lib, "EC_POINT_set_affine_coordinates_GFp"):
            self.set_affine_coordinates = lib.EC_POINT_set_affine_coordinates_GFp  # pyright: ignore
        elif hasattr(lib, "EC_POINT_set_affine_coordinates"):
            self.set_affine_coordinates = lib.EC_POINT_set_affine_coordinates  # pyright: ignore
        else:
            raise Exception(f"EC_POINT_set_affine_coordinates/GFp not available in lib {str(dir(lib))}")

        if hasattr(lib, "EC_POINT_get_affine_coordinates_GFp"):
            self.get_affine_coordinates = lib.EC_POINT_get_affine_coordinates_GFp  # pyright: ignore
        elif hasattr(lib, "EC_POINT_get_affine_coordinates"):
            self.get_affine_coordinates = lib.EC_POINT_get_affine_coordinates  # pyright: ignore
        else:
            raise Exception(f"EC_POINT_get_affine_coordinates/GFp not available in _lib [{str(dir(lib))}]")

    def int2bn(self, num: int) -> Any:
        binary = num.to_bytes((num.bit_length() + 7) >> 3, "big")
        bn = self.binding.lib.BN_bin2bn(binary, len(binary), self.binding.ffi.NULL)  # pyright: ignore
        if bn == self.binding.ffi.NULL:  # pyright: ignore
            raise Exception("BN_bin2bn returned NULL")
        return bn

    def bn2int(self, bn: Any) -> int:
        num_bytes = self.binding.lib.BN_num_bytes(bn)  # pyright: ignore
        binary = self.binding.ffi.new("unsigned char[]", num_bytes)  # pyright: ignore
        binary_len = self.binding.lib.BN_bn2bin(bn, binary)  # pyright: ignore
        if binary_len < 0:
            raise Exception("BN_bn2int failed")
        return int.from_bytes(self.binding.ffi.buffer(binary)[:binary_len], "big")  # pyright: ignore

    def point_multiply_x(self, public_key: EllipticCurvePublicKey, private_key: EllipticCurvePrivateKey) -> bytes:
        """Perform a point multiplication of the given public key with the private_key (scalar).
        Return the x component of the result."""
        ec_cdata = private_key._ec_key  # type: ignore
        group = self.binding.lib.EC_KEY_get0_group(ec_cdata)  # pyright: ignore

        point = self.binding.lib.EC_POINT_new(group)  # pyright: ignore
        if point == self.binding.ffi.NULL:  # pyright: ignore
            raise Exception("EC_POINT_new(group) returned NULL")
        result_point = self.binding.ffi.gc(point, self.binding.lib.EC_POINT_free)  # pyright: ignore

        # convert the public_key into a point
        pn = public_key.public_numbers()
        bn_x = self.binding.ffi.gc(self.int2bn(pn.x), self.binding.lib.BN_free)  # pyright: ignore
        bn_y = self.binding.ffi.gc(self.int2bn(pn.y), self.binding.lib.BN_free)  # pyright: ignore

        point = self.binding.lib.EC_POINT_new(group)  # pyright: ignore
        if point == self.binding.ffi.NULL:  # pyright: ignore
            raise Exception("EC_POINT_new(group) returned NULL")
        pubkey_point = self.binding.ffi.gc(point, self.binding.lib.EC_POINT_free)  # pyright: ignore

        # convert private key to scalar
        privkey_scalar = self.binding.ffi.gc(  # pyright: ignore
            self.int2bn(private_key.private_numbers().private_value),
            self.binding.lib.BN_free,  # pyright: ignore
        )

        bn_ctx = self.binding.lib.BN_CTX_new()  # pyright: ignore
        if bn_ctx == self.binding.ffi.NULL:  # pyright: ignore
            raise Exception("BN_CTX_new returned NULL")
        self.binding.lib.BN_CTX_start(bn_ctx)  # pyright: ignore
        try:
            res = self.set_affine_coordinates(group, pubkey_point, bn_x, bn_y, bn_ctx)
            if res != 1:
                raise Exception("set_affine_coordinates failed")

            res = self.binding.lib.EC_POINT_mul(  # pyright: ignore
                group, result_point, self.binding.ffi.NULL, pubkey_point, privkey_scalar, bn_ctx  # pyright: ignore
            )
            if res != 1:
                raise Exception("EC_POINT_mul failed")

            # return the x component of result_point
            bn_x2 = self.binding.lib.BN_CTX_get(bn_ctx)  # pyright: ignore
            res = self.get_affine_coordinates(
                group, result_point, bn_x2, self.binding.ffi.NULL, bn_ctx  # pyright: ignore
            )
            if res != 1:
                raise Exception("get_affine_coordinates failed")

            x: int = self.bn2int(bn_x2)
        finally:
            self.binding.lib.BN_CTX_end(bn_ctx)  # pyright: ignore
            self.binding.lib.BN_CTX_free(bn_ctx)  # pyright: ignore

        return x.to_bytes((x.bit_length() + 7) >> 3, "big")
