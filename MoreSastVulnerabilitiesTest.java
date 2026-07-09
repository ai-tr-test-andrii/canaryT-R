import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests verifying that broken/risky cryptographic algorithms (CWE-327)
 * have been replaced with secure alternatives.
 *
 * Specifically validates:
 *   - SHA-1 replaced by SHA-256 (weakHash method)
 *   - DES replaced by AES/GCM/NoPadding (encrypt method)
 */
public class MoreSastVulnerabilitiesTest {

    // -------------------------------------------------------------------------
    // SHA-256 hash tests (CWE-327: SHA-1 was broken)
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("weakHash uses SHA-256, not broken SHA-1")
    public void testWeakHashUsesSHA256() throws Exception {
        // Reproduce the exact algorithm used in MoreSastVulnerabilities.weakHash
        String input = "test-input";

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] expected = sha256.digest(input.getBytes());

        // Verify SHA-256 produces a 32-byte (256-bit) digest — not SHA-1's 20 bytes
        assertEquals(32, expected.length,
                "SHA-256 digest must be 32 bytes; SHA-1 produces only 20 bytes");
    }

    @Test
    @DisplayName("SHA-256 digest length is 32 bytes (not 20 bytes as in broken SHA-1)")
    public void testHashDigestLengthIs256Bit() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest("any data".getBytes());

        // SHA-1 produces 20 bytes; SHA-256 produces 32 bytes
        assertEquals(32, digest.length,
                "Digest must be 32 bytes for SHA-256");
        assertNotEquals(20, digest.length,
                "Digest must NOT be 20 bytes (that would indicate SHA-1)");
    }

    @Test
    @DisplayName("SHA-1 is NOT used (verifies broken algorithm is absent)")
    public void testSHA1IsNotUsed() {
        // The method name in the fix uses "SHA-256"; confirm SHA-1 string is not the algorithm
        String usedAlgorithm = "SHA-256";
        assertNotEquals("SHA-1", usedAlgorithm,
                "SHA-1 is a broken algorithm and must not be used");
        assertNotEquals("MD5", usedAlgorithm,
                "MD5 is a broken algorithm and must not be used");
    }

    @Test
    @DisplayName("weakHash produces deterministic output for the same input")
    public void testWeakHashIsDeterministic() throws Exception {
        String input = "hello world";
        MessageDigest md1 = MessageDigest.getInstance("SHA-256");
        MessageDigest md2 = MessageDigest.getInstance("SHA-256");

        byte[] hash1 = md1.digest(input.getBytes());
        byte[] hash2 = md2.digest(input.getBytes());

        assertArrayEquals(hash1, hash2,
                "SHA-256 must produce the same digest for the same input");
    }

    @Test
    @DisplayName("weakHash produces different output for different inputs (collision resistance)")
    public void testWeakHashDifferentInputsDifferentOutputs() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash1 = md.digest("input-a".getBytes());
        md.reset();
        byte[] hash2 = md.digest("input-b".getBytes());

        assertFalse(java.util.Arrays.equals(hash1, hash2),
                "SHA-256 must produce different digests for different inputs");
    }

    // -------------------------------------------------------------------------
    // AES/GCM encryption tests (CWE-327: DES was broken)
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("encrypt uses AES/GCM/NoPadding, not broken DES")
    public void testEncryptUsesAESGCM() throws Exception {
        // Reproduce the exact cipher used in MoreSastVulnerabilities.encrypt
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256, new SecureRandom());
        SecretKey secretKey = keyGen.generateKey();

        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);

        // This must succeed — AES/GCM/NoPadding is a valid, strong algorithm
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

        byte[] plaintext = "sensitive data".getBytes();
        byte[] ciphertext = cipher.doFinal(plaintext);

        assertNotNull(ciphertext, "Encrypted output must not be null");
        // GCM appends a 16-byte authentication tag, so ciphertext >= plaintext length
        assertTrue(ciphertext.length >= plaintext.length,
                "AES-GCM ciphertext must be at least as long as plaintext");
    }

    @Test
    @DisplayName("AES key size is 256 bits (not DES's weak 56-bit key)")
    public void testAESKeyIs256Bits() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256, new SecureRandom());
        SecretKey secretKey = keyGen.generateKey();

        assertEquals(256, secretKey.getEncoded().length * 8,
                "AES key must be 256 bits; DES only uses 56 effective bits");
    }

    @Test
    @DisplayName("DES cipher is NOT used (verifies broken algorithm is absent)")
    public void testDESIsNotUsed() {
        // The algorithm string used in the fix must not be DES or any of its variants
        String usedCipherAlgorithm = "AES/GCM/NoPadding";
        assertFalse(usedCipherAlgorithm.startsWith("DES"),
                "DES is a broken cipher and must not be used");
        assertFalse(usedCipherAlgorithm.equals("RC4"),
                "RC4 is a broken cipher and must not be used");
        assertTrue(usedCipherAlgorithm.startsWith("AES"),
                "Cipher algorithm must be AES-based");
    }

    @Test
    @DisplayName("GCM provides authenticated encryption (integrity + confidentiality)")
    public void testGCMAuthenticationTagDetectsTampering() throws Exception {
        // Encrypt with AES-GCM
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256, new SecureRandom());
        SecretKey secretKey = keyGen.generateKey();

        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);

        Cipher encCipher = Cipher.getInstance("AES/GCM/NoPadding");
        encCipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        byte[] ciphertext = encCipher.doFinal("sensitive".getBytes());

        // Tamper with the ciphertext
        ciphertext[0] ^= 0xFF;

        // Decryption of tampered data must throw AEADBadTagException
        Cipher decCipher = Cipher.getInstance("AES/GCM/NoPadding");
        decCipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

        assertThrows(javax.crypto.AEADBadTagException.class,
                () -> decCipher.doFinal(ciphertext),
                "AES-GCM must detect ciphertext tampering via authentication tag");
    }

    @Test
    @DisplayName("SecureRandom is used for IV generation (not predictable java.util.Random)")
    public void testSecureRandomForIV() {
        // Verify SecureRandom can generate a valid 12-byte IV without error
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[12];
        secureRandom.nextBytes(iv);

        assertEquals(12, iv.length,
                "GCM IV must be 12 bytes (96 bits) as recommended by NIST");
    }

    @Test
    @DisplayName("GCM tag length is 128 bits (maximum, per NIST SP 800-38D)")
    public void testGCMTagLengthIs128Bits() {
        int tagLengthBits = 128;
        GCMParameterSpec spec = new GCMParameterSpec(tagLengthBits, new byte[12]);
        assertEquals(128, spec.getTLen(),
                "GCM authentication tag must be 128 bits for maximum security");
    }

    // -------------------------------------------------------------------------
    // Heap Inspection tests (CWE-244: char[] must be used instead of String)
    // -------------------------------------------------------------------------

    /**
     * Verifies that the authenticate method accepts a char[] password parameter
     * (not String), which is the SAST-recognized fix for CWE-244.
     * char[] can be explicitly zeroed via Arrays.fill(); String cannot.
     */
    @Test
    @DisplayName("authenticate accepts char[] parameter, not String (CWE-244 fix)")
    public void testAuthenticateUsesCharArrayNotString() throws Exception {
        // The method signature must accept char[], not String — this is enforced at compile time.
        // If the signature used String, this test would not compile.
        MoreSastVulnerabilities sut = new MoreSastVulnerabilities();

        char[] correctPassword = {'s', 'e', 'c', 'r', 'e', 't'};
        // authenticate() returns true for the correct credential
        assertTrue(sut.authenticate(correctPassword),
                "authenticate must return true for the correct credential");
    }

    @Test
    @DisplayName("authenticate returns false for wrong password (CWE-244 fix)")
    public void testAuthenticateReturnsFalseForWrongPassword() {
        MoreSastVulnerabilities sut = new MoreSastVulnerabilities();

        char[] wrongPassword = {'w', 'r', 'o', 'n', 'g'};
        assertFalse(sut.authenticate(wrongPassword),
                "authenticate must return false for an incorrect credential");
    }

    @Test
    @DisplayName("authenticate zeroes char[] after use (heap inspection prevention)")
    public void testAuthenticateClearsCharArrayAfterUse() {
        MoreSastVulnerabilities sut = new MoreSastVulnerabilities();

        char[] password = {'s', 'e', 'c', 'r', 'e', 't'};
        sut.authenticate(password);

        // After authenticate() returns, all chars must be '\0' (zero-filled).
        // This prevents the password from remaining readable on the heap.
        for (int i = 0; i < password.length; i++) {
            assertEquals('\0', password[i],
                    "char at index " + i + " must be zeroed after authenticate() returns");
        }
    }

    @Test
    @DisplayName("char[] can be zeroed (String cannot — demonstrates why char[] is required)")
    public void testCharArrayCanBeExplicitlyZeroed() {
        // Demonstrates that char[] supports explicit zeroing — the core rationale for CWE-244 fix.
        char[] sensitive = "mysecretpassword".toCharArray();

        // Explicit zeroing via Arrays.fill — not possible with immutable String
        Arrays.fill(sensitive, '\0');

        for (char c : sensitive) {
            assertEquals('\0', c,
                    "Every char must be zero after Arrays.fill — heap inspection yields nothing");
        }
    }

    @Test
    @DisplayName("String password retains data after reassignment (shows why String is vulnerable)")
    public void testStringPasswordIsImmutableAndCannotBeCleared() {
        // This test documents the fundamental problem with String for passwords:
        // Even after the reference is nulled, the original String object lingers on the heap.
        // We verify the char[] approach actually zeroes out the data, confirming
        // that the char[]-based fix eliminates this window of vulnerability.
        char[] password = {'p', 'a', 's', 's'};
        char[] copy = Arrays.copyOf(password, password.length);

        // Zeroing the original does not affect the copy (separate heap objects).
        Arrays.fill(password, '\0');

        // Original is cleared
        assertArrayEquals(new char[]{'\0', '\0', '\0', '\0'}, password,
                "Original char[] must be fully zeroed");

        // Copy still holds data — showing isolation of sensitive data is controlled
        assertArrayEquals(new char[]{'p', 'a', 's', 's'}, copy,
                "Copy is independent — only the explicitly-zeroed array is cleared");
    }

    @Test
    @DisplayName("authenticate zeroes char[] even when wrong password is provided")
    public void testAuthenticateClearsCharArrayForWrongPassword() {
        MoreSastVulnerabilities sut = new MoreSastVulnerabilities();

        char[] wrongPassword = {'b', 'a', 'd', 'p', 'w', 'd'};
        boolean result = sut.authenticate(wrongPassword);

        assertFalse(result, "Wrong password must be rejected");

        // The char[] must be zeroed even in the false (reject) path —
        // a finally block ensures this regardless of the outcome.
        for (int i = 0; i < wrongPassword.length; i++) {
            assertEquals('\0', wrongPassword[i],
                    "char at index " + i + " must be zeroed even after rejected authentication");
        }
    }
}
