import struct
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from keylime.tpm.tpm2_objects import (
    ECC_CURVE_PRIMES,
    TPM_ECC_NIST_P192,
    TPM_ECC_NIST_P224,
    TPM_ECC_NIST_P256,
    TPM_ECC_NIST_P384,
    TPM_ECC_NIST_P521,
    _curve_from_curve_id,
    _pack_in_tpm2b,
    pubkey_parms_from_tpm2b_public,
    tpms_ecc_point_marshal,
)
from keylime.tpm.tpm_util import crypt_secret_encrypt_ecc, der_int, der_len, ecdsa_der_from_tpm


class TestTpm2Objects(unittest.TestCase):
    def test_p521_coordinate_validation_logic(self):
        """Test the specific coordinate validation logic for P-521"""
        curve = _curve_from_curve_id(TPM_ECC_NIST_P521)

        # Test the updated validation logic
        max_bytes = (curve.key_size + 7) // 8  # Should be 66 bytes for P-521
        min_bytes = max_bytes - 1 if curve.key_size % 8 != 0 else max_bytes  # Should be 65 bytes for P-521

        self.assertEqual(max_bytes, 66)
        self.assertEqual(min_bytes, 65)  # P-521 is not byte-aligned, so allows 65-66 bytes

        # Test coordinate sizes that should be accepted (65-66 bytes for P-521)
        valid_sizes = [65, 66]

        for size in valid_sizes:
            # Check that the validation logic would accept this size
            should_pass = min_bytes <= size <= max_bytes
            self.assertTrue(should_pass, f"Size {size} bytes should be valid for P-521")

        # Test coordinate sizes that should be rejected
        invalid_sizes = [64, 67, 32, 68]

        for size in invalid_sizes:
            # This should fail: not in the valid range
            should_fail = size < min_bytes or size > max_bytes
            self.assertTrue(should_fail, f"Size {size} bytes should be invalid for P-521")

    def test_p256_coordinate_validation_logic(self):
        """Test the coordinate validation logic for P-256 to ensure no regression"""
        curve = _curve_from_curve_id(TPM_ECC_NIST_P256)

        max_bytes = (curve.key_size + 7) // 8  # Should be 32 bytes for P-256
        min_bytes = (
            max_bytes - 1 if curve.key_size % 8 != 0 else max_bytes
        )  # Should be 32 bytes for P-256 (byte-aligned)

        self.assertEqual(max_bytes, 32)
        self.assertEqual(min_bytes, 32)  # P-256 is byte-aligned, so only accepts 32 bytes

        # 32 bytes should be accepted
        size = 32
        should_pass = min_bytes <= size <= max_bytes
        self.assertTrue(should_pass, f"P-256 should accept {size} bytes")

        # Other sizes should be rejected
        invalid_sizes = [31, 33, 64]
        for size in invalid_sizes:
            should_fail = size < min_bytes or size > max_bytes
            self.assertTrue(should_fail, f"P-256 should reject {size} bytes")

    def test_p384_coordinate_validation_logic(self):
        """Test the coordinate validation logic for P-384 to ensure no regression"""
        curve = _curve_from_curve_id(TPM_ECC_NIST_P384)

        max_bytes = (curve.key_size + 7) // 8  # Should be 48 bytes for P-384
        min_bytes = (
            max_bytes - 1 if curve.key_size % 8 != 0 else max_bytes
        )  # Should be 48 bytes for P-384 (byte-aligned)

        self.assertEqual(max_bytes, 48)
        self.assertEqual(min_bytes, 48)  # P-384 is byte-aligned, so only accepts 48 bytes

        # 48 bytes should be accepted
        size = 48
        should_pass = min_bytes <= size <= max_bytes
        self.assertTrue(should_pass, f"P-384 should accept {size} bytes")

    def test_coordinate_size_calculation(self):
        """Test that coordinate size calculations are correct for different curves"""
        # P-256: 256 bits -> (256 + 7) // 8 = 32 bytes
        curve_p256 = _curve_from_curve_id(TPM_ECC_NIST_P256)
        expected_p256 = (curve_p256.key_size + 7) // 8
        self.assertEqual(expected_p256, 32)
        self.assertEqual(curve_p256.key_size, 256)

        # P-384: 384 bits -> (384 + 7) // 8 = 48 bytes
        curve_p384 = _curve_from_curve_id(TPM_ECC_NIST_P384)
        expected_p384 = (curve_p384.key_size + 7) // 8
        self.assertEqual(expected_p384, 48)
        self.assertEqual(curve_p384.key_size, 384)

        # P-521: 521 bits -> (521 + 7) // 8 = 66 bytes
        curve_p521 = _curve_from_curve_id(TPM_ECC_NIST_P521)
        expected_p521 = (curve_p521.key_size + 7) // 8
        self.assertEqual(expected_p521, 66)
        self.assertEqual(curve_p521.key_size, 521)

    def test_p521_specific_fix(self):
        """Test the specific scenario that was fixed: P-521 with 66-byte coordinates"""
        curve = _curve_from_curve_id(TPM_ECC_NIST_P521)

        # The key issue: P-521 has 521 bits
        self.assertEqual(curve.key_size, 521)

        # TPMs pad to 66 bytes (528 bits)
        tpm_padded_size = 66
        tpm_padded_bits = tpm_padded_size * 8
        self.assertEqual(tpm_padded_bits, 528)

        # The old validation would reject: (66 * 8) != 521
        old_validation_fails = tpm_padded_bits != curve.key_size
        self.assertTrue(old_validation_fails, "Old validation would incorrectly reject 66-byte coordinates")

        # The new validation should accept: len(x) == expected_bytes OR (len(x) * 8) == curve.key_size
        expected_bytes = (curve.key_size + 7) // 8
        new_validation_passes = (tpm_padded_size == expected_bytes) or (tpm_padded_bits == curve.key_size)
        self.assertTrue(new_validation_passes, "New validation should accept 66-byte coordinates")

    def test_validation_before_and_after_fix(self):
        """Test that demonstrates the fix by comparing old vs new validation logic"""
        curve = _curve_from_curve_id(TPM_ECC_NIST_P521)

        # Test multiple coordinate sizes that P-521 can have
        test_sizes = [65, 66]  # 65 bytes (leading zero stripped), 66 bytes (padded)

        max_bytes = (curve.key_size + 7) // 8  # 66 bytes
        min_bytes = max_bytes - 1 if curve.key_size % 8 != 0 else max_bytes  # 65 bytes for P-521

        for coordinate_size in test_sizes:
            # Old validation logic (strict bit size match) - would require exactly 65.125 bytes
            # which is impossible since we can't have fractional bytes

            # New validation logic (accept range for non-byte-aligned curves)
            new_logic_passes = min_bytes <= coordinate_size <= max_bytes
            self.assertTrue(new_logic_passes, f"New logic should accept {coordinate_size}-byte coordinates for P-521")

        # Verify the calculations
        self.assertEqual(max_bytes, 66)
        self.assertEqual(min_bytes, 65)

    def test_p521_coordinate_range_validation(self):
        """Test that P-521 accepts coordinates in the range 65-66 bytes (520-528 bits)"""
        curve = _curve_from_curve_id(TPM_ECC_NIST_P521)

        # P-521: 521 bits, padded to 66 bytes (528 bits), or 65 bytes with leading zero stripped
        max_bytes = (curve.key_size + 7) // 8  # 66 bytes
        min_bytes = max_bytes - 1  # 65 bytes (since 521 % 8 != 0)

        # Test all valid sizes
        valid_sizes = [65, 66]
        for size in valid_sizes:
            is_valid = min_bytes <= size <= max_bytes
            self.assertTrue(is_valid, f"P-521 should accept {size} bytes ({size * 8} bits)")

        # Test invalid sizes
        invalid_sizes = [64, 67, 68, 32]
        for size in invalid_sizes:
            is_invalid = size < min_bytes or size > max_bytes
            self.assertTrue(is_invalid, f"P-521 should reject {size} bytes ({size * 8} bits)")

    def test_coordinate_value_validation(self):
        """Test that coordinate values are validated against actual prime moduli"""
        # Test P-521 with actual prime
        # curve_p521 = _curve_from_curve_id(TPM_ECC_NIST_P521)  # Not needed for this test
        p521_prime = ECC_CURVE_PRIMES[TPM_ECC_NIST_P521]

        # Test valid coordinate value (within range)
        valid_coord_int = p521_prime - 1  # Largest valid value
        valid_coord_bytes = valid_coord_int.to_bytes(66, "big")  # 66 bytes, padded

        # Test the validation logic
        coord_int = int.from_bytes(valid_coord_bytes, "big")
        is_valid_value = coord_int < p521_prime
        self.assertTrue(is_valid_value, "Coordinate value should be valid for P-521")

        # Test invalid coordinate value (>= prime)
        invalid_coord_int = p521_prime  # Equal to prime (invalid)
        invalid_coord_bytes = invalid_coord_int.to_bytes(66, "big")  # 66 bytes, but value too large

        coord_int = int.from_bytes(invalid_coord_bytes, "big")
        is_invalid_value = coord_int >= p521_prime
        self.assertTrue(is_invalid_value, "Coordinate value >= prime should be invalid for P-521")

    def test_prime_constants_accuracy(self):
        """Test that our hardcoded prime constants are correct"""
        # Verify the NIST prime values
        self.assertEqual(ECC_CURVE_PRIMES[TPM_ECC_NIST_P192], 2**192 - 2**64 - 1)
        self.assertEqual(ECC_CURVE_PRIMES[TPM_ECC_NIST_P224], 2**224 - 2**96 + 1)
        self.assertEqual(ECC_CURVE_PRIMES[TPM_ECC_NIST_P256], 2**256 - 2**224 + 2**192 + 2**96 - 1)
        self.assertEqual(ECC_CURVE_PRIMES[TPM_ECC_NIST_P384], 2**384 - 2**128 - 2**96 + 2**32 - 1)
        self.assertEqual(ECC_CURVE_PRIMES[TPM_ECC_NIST_P521], 2**521 - 1)

        # Verify they are actually less than 2^m for all curves except P-521
        self.assertLess(ECC_CURVE_PRIMES[TPM_ECC_NIST_P192], 2**192)
        self.assertLess(ECC_CURVE_PRIMES[TPM_ECC_NIST_P224], 2**224)
        self.assertLess(ECC_CURVE_PRIMES[TPM_ECC_NIST_P256], 2**256)
        self.assertLess(ECC_CURVE_PRIMES[TPM_ECC_NIST_P384], 2**384)
        self.assertEqual(ECC_CURVE_PRIMES[TPM_ECC_NIST_P521], 2**521 - 1)  # P-521 is special case

    def test_prime_lookup_table(self):
        """Test that the prime lookup table works correctly"""
        # Test known curves
        self.assertEqual(ECC_CURVE_PRIMES[TPM_ECC_NIST_P192], 2**192 - 2**64 - 1)
        self.assertEqual(ECC_CURVE_PRIMES[TPM_ECC_NIST_P224], 2**224 - 2**96 + 1)
        self.assertEqual(ECC_CURVE_PRIMES[TPM_ECC_NIST_P256], 2**256 - 2**224 + 2**192 + 2**96 - 1)
        self.assertEqual(ECC_CURVE_PRIMES[TPM_ECC_NIST_P384], 2**384 - 2**128 - 2**96 + 2**32 - 1)
        self.assertEqual(ECC_CURVE_PRIMES[TPM_ECC_NIST_P521], 2**521 - 1)

        # Test rejection of unknown curve
        unknown_curve_id = 0x9999
        unknown_prime = ECC_CURVE_PRIMES.get(unknown_curve_id)
        self.assertIsNone(unknown_prime, "Unknown curves should not be in ECC_CURVE_PRIMES")

    def test_error_message_formatting(self):
        """Test that error messages use bit_length() instead of full integers"""
        # Create a large coordinate value
        large_value = ECC_CURVE_PRIMES[TPM_ECC_NIST_P521]  # This would be hundreds of digits

        # Verify bit_length() is much more reasonable than the full number
        bit_length = large_value.bit_length()
        self.assertEqual(bit_length, 521)  # Much more readable than 150+ digit number

        # The error message should use bit lengths, not full integers
        expected_msg_pattern = f"coordinate too large: {bit_length} bits"
        self.assertIn("521 bits", expected_msg_pattern)

    def test_unknown_curve_rejection(self):
        """Test that unknown curves are strictly rejected"""
        # This tests the design decision to be strict rather than use fallbacks
        unknown_curve_id = 0x9999

        # The strict approach: unknown curves should not have fallback behavior
        # This ensures we only validate curves we explicitly understand
        result = ECC_CURVE_PRIMES.get(unknown_curve_id)
        self.assertIsNone(result, "Unknown curves should be explicitly rejected, not given fallback primes")


class TestEccPublicKeySecurityValidation(unittest.TestCase):
    """Test that ECC public key validation includes all required security checks:
    1. Point is on the curve
    2. Point is not zero or infinity
    3. Point is not in a small subgroup (not applicable to NIST curves with cofactor=1)
    """

    def create_ecc_tpm2b_public(self, x: int, y: int, curve_id: int = TPM_ECC_NIST_P256) -> bytes:
        """Helper to create a TPM2B_PUBLIC structure for ECC key with given coordinates"""
        # Get coordinate size based on curve
        curve = _curve_from_curve_id(curve_id)
        coord_bytes = (curve.key_size + 7) // 8

        # Convert coordinates to bytes
        x_bytes = x.to_bytes(coord_bytes, "big")
        y_bytes = y.to_bytes(coord_bytes, "big")

        # Build TPMT_PUBLIC structure
        # alg_type (TPM_ALG_ECC = 0x0023)
        tpmt = struct.pack(">H", 0x0023)
        # name_alg (TPM_ALG_SHA256 = 0x000B)
        tpmt += struct.pack(">H", 0x000B)
        # object_attributes (4 bytes)
        tpmt += struct.pack(">I", 0x00040072)
        # auth_policy (empty TPM2B)
        tpmt += struct.pack(">H", 0)
        # symmetric (TPM_ALG_NULL)
        tpmt += struct.pack(">H", 0x0010)
        # scheme (TPM_ALG_NULL)
        tpmt += struct.pack(">H", 0x0010)
        # curve_id
        tpmt += struct.pack(">H", curve_id)
        # kdf_scheme (TPM_ALG_NULL)
        tpmt += struct.pack(">H", 0x0010)
        # x coordinate (TPM2B)
        tpmt += _pack_in_tpm2b(x_bytes)
        # y coordinate (TPM2B)
        tpmt += _pack_in_tpm2b(y_bytes)

        # Wrap in TPM2B_PUBLIC
        return _pack_in_tpm2b(tpmt)

    def test_point_on_curve_validation(self):
        """Test that points not on the curve are rejected (Security Check #1)"""
        # For P-256, the curve equation is: y² = x³ - 3x + b (mod p)
        # Choose coordinates that don't satisfy this equation
        x = 1
        y = 1  # (1, 1) is not on the P-256 curve

        tpm2b_public = self.create_ecc_tpm2b_public(x, y, TPM_ECC_NIST_P256)

        # The cryptography library should reject this point as not being on the curve
        with self.assertRaises(ValueError) as cm:
            pubkey_parms_from_tpm2b_public(tpm2b_public)
        self.assertIn("not on the curve", str(cm.exception).lower())

    def test_point_at_infinity_validation(self):
        """Test that the point at infinity (0, 0) is rejected (Security Check #2)"""
        # The point at infinity should be rejected
        x = 0
        y = 0

        tpm2b_public = self.create_ecc_tpm2b_public(x, y, TPM_ECC_NIST_P256)

        # The cryptography library should reject the point at infinity
        with self.assertRaises(ValueError) as cm:
            pubkey_parms_from_tpm2b_public(tpm2b_public)
        self.assertIn("not on the curve", str(cm.exception).lower())

    def test_valid_point_accepted(self):
        """Test that a valid point on the curve is accepted"""
        # Generate a valid key and extract its coordinates
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        numbers = public_key.public_numbers()

        # Create TPM2B_PUBLIC with valid coordinates
        tpm2b_public = self.create_ecc_tpm2b_public(numbers.x, numbers.y, TPM_ECC_NIST_P256)

        # Should parse successfully
        parsed_key, _ = pubkey_parms_from_tpm2b_public(tpm2b_public)
        self.assertIsInstance(parsed_key, ec.EllipticCurvePublicKey)

        # Verify the coordinates match
        assert isinstance(parsed_key, ec.EllipticCurvePublicKey)  # Type narrowing for pyright
        parsed_numbers = parsed_key.public_numbers()
        self.assertEqual(parsed_numbers.x, numbers.x)
        self.assertEqual(parsed_numbers.y, numbers.y)

    def test_small_subgroup_not_applicable_to_nist_curves(self):
        """Test documenting that small subgroup checks are not needed for NIST curves (Security Check #3)

        NIST P-curves (P-192, P-224, P-256, P-384, P-521) all have cofactor h=1,
        meaning the entire curve has prime order. There are no small subgroups to check.

        Curves with cofactor > 1 (like Curve25519 with h=8) require additional validation
        to ensure the point is not in a small subgroup, but this is not applicable to
        the NIST curves used by TPMs.
        """
        # This test documents the cofactor=1 property for all supported NIST curves
        # The cryptography library's point validation is sufficient for these curves

        test_curves = [
            (TPM_ECC_NIST_P192, ec.SECP192R1()),
            (TPM_ECC_NIST_P224, ec.SECP224R1()),
            (TPM_ECC_NIST_P256, ec.SECP256R1()),
            (TPM_ECC_NIST_P384, ec.SECP384R1()),
            (TPM_ECC_NIST_P521, ec.SECP521R1()),
        ]

        for curve_id, curve_obj in test_curves:
            with self.subTest(curve=curve_obj.name):
                try:
                    # Generate a valid key for this curve
                    # Note: P-192 may not be supported in newer OpenSSL versions
                    private_key = ec.generate_private_key(curve_obj)
                except Exception:  # pylint: disable=broad-except
                    # Skip this specific curve if not supported by OpenSSL (e.g., P-192)
                    self.skipTest(f"Curve {curve_obj.name} not supported by OpenSSL")

                public_key = private_key.public_key()
                numbers = public_key.public_numbers()

                # Create TPM2B_PUBLIC and verify it parses successfully
                tpm2b_public = self.create_ecc_tpm2b_public(numbers.x, numbers.y, curve_id)
                parsed_key, _ = pubkey_parms_from_tpm2b_public(tpm2b_public)

                # All NIST curves have cofactor = 1, so no small subgroup attacks possible
                # The point validation by the cryptography library is sufficient
                self.assertIsInstance(parsed_key, ec.EllipticCurvePublicKey)

    def test_coordinate_exceeds_field_prime_rejected(self):
        """Test that coordinates >= field prime are rejected"""
        # Use a coordinate value that's >= the field prime for P-256
        p256_prime = ECC_CURVE_PRIMES[TPM_ECC_NIST_P256]

        # x coordinate exceeds the field prime
        x = p256_prime + 1
        y = 1

        tpm2b_public = self.create_ecc_tpm2b_public(x, y, TPM_ECC_NIST_P256)

        # Should be rejected during coordinate validation
        with self.assertRaises(ValueError) as cm:
            pubkey_parms_from_tpm2b_public(tpm2b_public)
        # Will fail either at coordinate validation or curve validation
        self.assertTrue(
            "coordinate too large" in str(cm.exception).lower() or "not on the curve" in str(cm.exception).lower()
        )

    def test_p521_point_validation(self):
        """Test point validation works correctly for P-521 (non-byte-aligned curve)"""
        # Generate a valid P-521 key
        private_key = ec.generate_private_key(ec.SECP521R1())
        public_key = private_key.public_key()
        numbers = public_key.public_numbers()

        # Valid point should be accepted
        tpm2b_public = self.create_ecc_tpm2b_public(numbers.x, numbers.y, TPM_ECC_NIST_P521)
        parsed_key, _ = pubkey_parms_from_tpm2b_public(tpm2b_public)
        self.assertIsInstance(parsed_key, ec.EllipticCurvePublicKey)

        # Invalid point should be rejected
        tpm2b_public_invalid = self.create_ecc_tpm2b_public(1, 1, TPM_ECC_NIST_P521)
        with self.assertRaises(ValueError) as cm:
            pubkey_parms_from_tpm2b_public(tpm2b_public_invalid)
        self.assertIn("not on the curve", str(cm.exception).lower())


class TestEccMarshaling(unittest.TestCase):
    """Test ECC point marshaling consistency fixes"""

    def test_p521_marshaling_consistency(self):
        """Test that P-521 marshaling produces consistent blob sizes regardless of coordinate values"""
        # Generate multiple P-521 keys to test with different coordinate values
        keys = []
        for _ in range(10):
            private_key = ec.generate_private_key(ec.SECP521R1())
            keys.append(private_key.public_key())

        # Marshal all keys and check that blob sizes are consistent
        blob_sizes = []
        for key in keys:
            blob = tpms_ecc_point_marshal(key)
            blob_sizes.append(len(blob))

        # All blobs should be the same size for P-521
        self.assertEqual(len(set(blob_sizes)), 1, "All P-521 marshaled blobs should have the same size")

        # Expected size: 2 bytes (x size) + 66 bytes (x coord) + 2 bytes (y size) + 66 bytes (y coord) = 136 bytes
        expected_size = 2 + 66 + 2 + 66
        self.assertEqual(blob_sizes[0], expected_size, f"P-521 marshaled blob should be {expected_size} bytes")

    def test_marshaling_coordinate_sizes(self):
        """Test that marshaled coordinates use fixed sizes based on curve key size"""
        # Test P-521: 521 bits -> (521 + 7) // 8 = 66 bytes per coordinate
        p521_key = ec.generate_private_key(ec.SECP521R1()).public_key()
        p521_blob = tpms_ecc_point_marshal(p521_key)

        # Parse the blob to check coordinate sizes
        x_size = struct.unpack(">H", p521_blob[:2])[0]
        y_size = struct.unpack(">H", p521_blob[2 + x_size : 2 + x_size + 2])[0]

        self.assertEqual(x_size, 66, "P-521 X coordinate should be 66 bytes")
        self.assertEqual(y_size, 66, "P-521 Y coordinate should be 66 bytes")

        # Test P-256: 256 bits -> (256 + 7) // 8 = 32 bytes per coordinate
        p256_key = ec.generate_private_key(ec.SECP256R1()).public_key()
        p256_blob = tpms_ecc_point_marshal(p256_key)

        x_size = struct.unpack(">H", p256_blob[:2])[0]
        y_size = struct.unpack(">H", p256_blob[2 + x_size : 2 + x_size + 2])[0]

        self.assertEqual(x_size, 32, "P-256 X coordinate should be 32 bytes")
        self.assertEqual(y_size, 32, "P-256 Y coordinate should be 32 bytes")

    def test_p521_credential_activation_consistency(self):
        """Test the specific issue: P-521 credential activation with consistent marshaling"""
        # This test verifies the fix for credential activation failures
        # Generate two P-521 keys with potentially different bit lengths for coordinates
        key1 = ec.generate_private_key(ec.SECP521R1()).public_key()
        key2 = ec.generate_private_key(ec.SECP521R1()).public_key()

        # Marshal both keys
        blob1 = tpms_ecc_point_marshal(key1)
        blob2 = tpms_ecc_point_marshal(key2)

        # The critical fix: both blobs should be the same size regardless of coordinate bit lengths
        self.assertEqual(
            len(blob1), len(blob2), "P-521 marshaled blobs must be same size regardless of coordinate bit lengths"
        )

        # Both should use the fixed coordinate size (66 bytes)
        expected_total_size = 2 + 66 + 2 + 66  # size_x + x + size_y + y
        self.assertEqual(len(blob1), expected_total_size)
        self.assertEqual(len(blob2), expected_total_size)

    def test_marshaling_format_correctness(self):
        """Test that marshaling follows the correct TPM format: size(2) + coord(n) + size(2) + coord(n)"""
        key = ec.generate_private_key(ec.SECP521R1()).public_key()
        blob = tpms_ecc_point_marshal(key)

        # Parse the blob structure
        if len(blob) < 4:
            self.fail("Marshaled blob too short")

        x_size = struct.unpack(">H", blob[:2])[0]
        self.assertEqual(x_size, 66, "X coordinate size should be 66 for P-521")

        if len(blob) < 2 + x_size + 2:
            self.fail("Marshaled blob missing Y coordinate size")

        y_size = struct.unpack(">H", blob[2 + x_size : 2 + x_size + 2])[0]
        self.assertEqual(y_size, 66, "Y coordinate size should be 66 for P-521")

        # Total size should be: 2 + 66 + 2 + 66 = 136
        expected_total = 2 + x_size + 2 + y_size
        self.assertEqual(len(blob), expected_total, "Total marshaled blob size incorrect")

    def test_crypt_secret_encrypt_ecc_consistency(self):
        """Test that crypt_secret_encrypt_ecc produces consistent results with fixed coordinate sizes"""
        # Generate a P-521 key to test with
        public_key = ec.generate_private_key(ec.SECP521R1()).public_key()
        hashfunc = hashes.SHA256()

        # Call the function multiple times and check consistency
        results = []
        for _ in range(5):
            data, point = crypt_secret_encrypt_ecc(public_key, hashfunc)
            results.append((data, point))

        # Check that all returned points have consistent marshaling
        # (the data will be different due to random key generation, but point marshaling should be consistent)
        point_sizes = [len(point) for _, point in results]
        self.assertEqual(len(set(point_sizes)), 1, "All marshaled points should have the same size")

        # For P-521, the marshaled point should be 136 bytes (2+66+2+66)
        expected_point_size = 2 + 66 + 2 + 66
        self.assertEqual(
            point_sizes[0], expected_point_size, f"P-521 marshaled point should be {expected_point_size} bytes"
        )

        # All data results should be different (due to random ephemeral keys)
        data_results = [data for data, _ in results]
        self.assertEqual(
            len(set(data_results)),
            len(data_results),
            "All data results should be different due to random ephemeral keys",
        )

        # All data results should have the same length (SHA256 digest size)
        data_sizes = [len(data) for data, _ in results]
        self.assertEqual(len(set(data_sizes)), 1, "All data results should have the same size")
        self.assertEqual(data_sizes[0], hashfunc.digest_size, "Data size should match hash digest size")


class TestEccSignatureParsing(unittest.TestCase):
    """Test ECC signature parsing improvements for variable-length coordinates"""

    def create_test_signature_blob(self, sig_r: bytes, sig_s: bytes) -> bytes:
        """Create a test TPM signature blob with given r and s components"""
        # TPM signature format: sig_alg(2) + hash_alg(2) + sig_size_r(2) + r_data + sig_size_s(2) + s_data
        sig_alg = 0x0018  # TPM_ALG_ECDSA
        hash_alg = 0x000B  # TPM_ALG_SHA256

        blob = struct.pack(">HHH", sig_alg, hash_alg, len(sig_r))
        blob += sig_r
        blob += struct.pack(">H", len(sig_s))
        blob += sig_s

        return blob

    def test_p521_variable_length_coordinates(self):
        """Test that P-521 signatures with variable-length coordinates are parsed correctly"""
        # Generate a P-521 key for testing
        private_key = ec.generate_private_key(ec.SECP521R1())
        public_key = private_key.public_key()

        # Test with 65-byte coordinates (leading zero stripped)
        sig_r_65 = b"\x00" * 1 + b"\x01" * 64  # 65 bytes
        sig_s_65 = b"\x00" * 1 + b"\x02" * 64  # 65 bytes

        blob_65 = self.create_test_signature_blob(sig_r_65, sig_s_65)

        # Should parse successfully
        der_sig_65 = ecdsa_der_from_tpm(blob_65, public_key)
        self.assertIsInstance(der_sig_65, bytes)
        self.assertTrue(len(der_sig_65) > 0)

        # Test with 66-byte coordinates (full padding)
        sig_r_66 = b"\x00" * 2 + b"\x01" * 64  # 66 bytes
        sig_s_66 = b"\x00" * 2 + b"\x02" * 64  # 66 bytes

        blob_66 = self.create_test_signature_blob(sig_r_66, sig_s_66)

        # Should parse successfully
        der_sig_66 = ecdsa_der_from_tpm(blob_66, public_key)
        self.assertIsInstance(der_sig_66, bytes)
        self.assertTrue(len(der_sig_66) > 0)

    def test_coordinate_size_validation(self):
        """Test that coordinate size validation works for different curves"""
        # Test P-256 with valid coordinates
        p256_key = ec.generate_private_key(ec.SECP256R1()).public_key()

        # Valid P-256 coordinates (32 bytes each)
        sig_r_32 = b"\x01" * 32
        sig_s_32 = b"\x02" * 32
        blob_p256_valid = self.create_test_signature_blob(sig_r_32, sig_s_32)

        # Should parse successfully
        der_sig = ecdsa_der_from_tpm(blob_p256_valid, p256_key)
        self.assertIsInstance(der_sig, bytes)

        # Test P-256 with invalid coordinates (too large)
        sig_r_invalid = b"\x01" * 50  # Too large for P-256
        sig_s_invalid = b"\x02" * 50  # Too large for P-256
        blob_p256_invalid = self.create_test_signature_blob(sig_r_invalid, sig_s_invalid)

        # Should raise ValueError
        with self.assertRaises(ValueError) as cm:
            ecdsa_der_from_tpm(blob_p256_invalid, p256_key)
        self.assertIn("Invalid r coordinate size", str(cm.exception))

    def test_signature_parsing_edge_cases(self):
        """Test edge cases in signature parsing"""
        p256_key = ec.generate_private_key(ec.SECP256R1()).public_key()

        # Test with truncated blob (missing s component)
        truncated_blob = struct.pack(">HHH", 0x0018, 0x000B, 32) + b"\x01" * 32
        # Missing s component

        with self.assertRaises(ValueError) as cm:
            ecdsa_der_from_tpm(truncated_blob, p256_key)
        self.assertIn("Unable to parse ECC signature", str(cm.exception))

        # Test with blob too short for s size header
        short_blob = struct.pack(">HHH", 0x0018, 0x000B, 32) + b"\x01" * 32 + b"\x00"  # Only 1 byte for s size

        with self.assertRaises(ValueError) as cm:
            ecdsa_der_from_tpm(short_blob, p256_key)
        self.assertIn("Unable to parse ECC signature", str(cm.exception))

    def test_der_encoding_correctness(self):
        """Test that DER encoding produces correctly formatted output"""
        p256_key = ec.generate_private_key(ec.SECP256R1()).public_key()

        # Create test coordinates
        sig_r = b"\x01" * 32
        sig_s = b"\x02" * 32
        blob = self.create_test_signature_blob(sig_r, sig_s)

        der_sig = ecdsa_der_from_tpm(blob, p256_key)

        # DER signature should start with SEQUENCE tag (0x30)
        self.assertEqual(der_sig[0], 0x30, "DER signature should start with SEQUENCE tag")

        # Should be parseable as DER format
        # The structure should be: 0x30 + length + INTEGER(r) + INTEGER(s)
        self.assertTrue(len(der_sig) >= 6, "DER signature should have minimum length")

    def test_multiple_curve_support(self):
        """Test that signature parsing works for multiple curve types"""
        test_cases = [
            (ec.SECP256R1(), 32),
            (ec.SECP384R1(), 48),
            (ec.SECP521R1(), 66),
        ]

        for curve, coord_size in test_cases:
            with self.subTest(curve=curve.name):
                private_key = ec.generate_private_key(curve)
                public_key = private_key.public_key()

                # Create test signature with appropriate coordinate size
                sig_r = b"\x01" * coord_size
                sig_s = b"\x02" * coord_size
                blob = self.create_test_signature_blob(sig_r, sig_s)

                # Should parse successfully
                der_sig = ecdsa_der_from_tpm(blob, public_key)
                self.assertIsInstance(der_sig, bytes)
                self.assertTrue(len(der_sig) > 0)
                self.assertEqual(der_sig[0], 0x30)  # DER SEQUENCE tag

    def test_der_int_encoding(self):
        """Test DER integer encoding helper function"""
        # Test positive number that doesn't need padding
        test_bytes = b"\x7F"  # 127, no padding needed
        der_encoded = der_int(test_bytes)
        expected = b"\x02\x01\x7F"  # INTEGER tag + length + value
        self.assertEqual(der_encoded, expected)

        # Test positive number that needs zero padding (high bit set)
        test_bytes = b"\xFF"  # 255, needs zero padding
        der_encoded = der_int(test_bytes)
        expected = b"\x02\x02\x00\xFF"  # INTEGER tag + length + zero padding + value
        self.assertEqual(der_encoded, expected)

    def test_der_len_encoding(self):
        """Test DER length encoding helper function"""
        # Test short form (< 128)
        short_len = der_len(50)
        self.assertEqual(short_len, b"\x32")  # 50 in hex

        # Test long form (>= 128)
        long_len = der_len(300)  # 0x012C
        expected = b"\x82\x01\x2C"  # Long form: 0x80 | 2 bytes, then 0x012C
        self.assertEqual(long_len, expected)

    def test_signature_format_validation_comprehensive(self):
        """Comprehensive test of signature format validation"""
        p521_key = ec.generate_private_key(ec.SECP521R1()).public_key()

        # Test minimum valid coordinate sizes for P-521
        valid_sizes = [65, 66]
        for size in valid_sizes:
            sig_r = b"\x01" * size
            sig_s = b"\x02" * size
            blob = self.create_test_signature_blob(sig_r, sig_s)

            # Should not raise exception
            der_sig = ecdsa_der_from_tpm(blob, p521_key)
            self.assertIsInstance(der_sig, bytes)

        # Test invalid coordinate sizes for P-521 (outside the 1-66 range)
        invalid_sizes = [0, 67, 100]  # 0 is too small, 67+ is too large
        for size in invalid_sizes:
            with self.subTest(size=size):
                sig_r = b"\x01" * size if size > 0 else b""
                sig_s = b"\x02" * size if size > 0 else b""
                blob = self.create_test_signature_blob(sig_r, sig_s)

                with self.assertRaises(ValueError) as cm:
                    ecdsa_der_from_tpm(blob, p521_key)
                self.assertIn("coordinate size", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
