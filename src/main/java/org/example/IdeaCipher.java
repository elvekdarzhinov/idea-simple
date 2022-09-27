package org.example;

public class IdeaCipher {

    public static final int BLOCK_SIZE = 8; // bytes
    public static int ROUNDS = 8;
    public static int KEY_SIZE = 16; // bytes

    private final int[] decryptionSubkeys;
    private final int[] encryptionSubkeys;

    public IdeaCipher(byte[] key) {
        encryptionSubkeys = generateSubkeys(key);
        decryptionSubkeys = invertSubkeys(encryptionSubkeys);
    }

    public byte[] crypt(byte[] data, int offset, boolean encrypt) {
        int[] subkeys = encrypt ? encryptionSubkeys : decryptionSubkeys;

        int x0 = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
        int x1 = ((data[offset + 2] & 0xFF) << 8) | (data[offset + 3] & 0xFF);
        int x2 = ((data[offset + 4] & 0xFF) << 8) | (data[offset + 5] & 0xFF);
        int x3 = ((data[offset + 6] & 0xFF) << 8) | (data[offset + 7] & 0xFF);

        int k = 0;
        for (int round = 0; round < ROUNDS; round++) {
            int s0 = mul(x0, subkeys[k++]);
            int s1 = add(x1, subkeys[k++]);
            int s2 = add(x2, subkeys[k++]);
            int s3 = mul(x3, subkeys[k++]);
            int s4 = s0 ^ s2;
            int s5 = s1 ^ s3;
            int s6 = mul(s4, subkeys[k++]);
            int s7 = add(s5, s6);
            int s8 = mul(s7, subkeys[k++]);
            int s9 = add(s6, s8);

            x0 = s0 ^ s8;
            x1 = s2 ^ s8;
            x2 = s1 ^ s9;
            x3 = s3 ^ s9;
        }

        int r0 = mul(x0, subkeys[k++]);
        int r1 = add(x2, subkeys[k++]);
        int r2 = add(x1, subkeys[k++]);
        int r3 = mul(x3, subkeys[k]);

        byte[] result = new byte[BLOCK_SIZE];

        result[0] = (byte) (r0 >> 8);
        result[1] = (byte) r0;
        result[2] = (byte) (r1 >> 8);
        result[3] = (byte) r1;
        result[4] = (byte) (r2 >> 8);
        result[5] = (byte) r2;
        result[6] = (byte) (r3 >> 8);
        result[7] = (byte) r3;

        return result;
    }

    private static int[] generateSubkeys(byte[] key) {
        if (key.length != KEY_SIZE) {
            throw new IllegalArgumentException(String.format("Key must be %d bytes long.", KEY_SIZE));
        }

        int[] subkeys = new int[ROUNDS * 6 + 4];

        for (int i = 0; i < KEY_SIZE / 2; i++) {
            subkeys[i] = ((key[2 * i] & 0xFF) << 8) | (key[2 * i + 1] & 0xFF);
        }
        for (int i = KEY_SIZE / 2; i < subkeys.length; i++) {
            int a = subkeys[(i + 1) % 8 != 0 ? i - 7 : i - 15] << 9;
            int b = subkeys[(i + 2) % 8 < 2 ? i - 14 : i - 6] >>> 7;
            subkeys[i] = (a | b) & 0xFFFF;
        }

        return subkeys;
    }

    public static int[] invertSubkeys(int[] subkeys) {
        int[] invSubkey = new int[subkeys.length];
        int p = 0;
        int i = ROUNDS * 6;
        // For the final output transformation (round 9)
        invSubkey[i] = mulInv(subkeys[p++]);         // 48 <- 0
        invSubkey[i + 1] = addInv(subkeys[p++]);     // 49 <- 1
        invSubkey[i + 2] = addInv(subkeys[p++]);     // 50 <- 2
        invSubkey[i + 3] = mulInv(subkeys[p++]);     // 51 <- 3
        // From round 8 to 2
        for (int r = ROUNDS - 1; r > 0; r--) {
            i = r * 6;
            invSubkey[i + 4] = subkeys[p++];         // 46 <- 4 ...
            invSubkey[i + 5] = subkeys[p++];         // 47 <- 5 ...
            invSubkey[i] = mulInv(subkeys[p++]);     // 42 <- 6 ...
            invSubkey[i + 2] = addInv(subkeys[p++]); // 44 <- 7 ...
            invSubkey[i + 1] = addInv(subkeys[p++]); // 43 <- 8 ...
            invSubkey[i + 3] = mulInv(subkeys[p++]); // 45 <- 9 ...
        }
        // Round 1
        invSubkey[4] = subkeys[p++];                 // 4 <- 46
        invSubkey[5] = subkeys[p++];                 // 5 <- 47
        invSubkey[0] = mulInv(subkeys[p++]);         // 0 <- 48
        invSubkey[1] = addInv(subkeys[p++]);         // 1 <- 49
        invSubkey[2] = addInv(subkeys[p++]);         // 2 <- 50
        invSubkey[3] = mulInv(subkeys[p]);           // 3 <- 51

        return invSubkey;
    }


    /**
     * Addition in the additive group (mod 2^16).
     * Range [0, 0xFFFF].
     */
    private static int add(int a, int b) {
        return (a + b) & 0xFFFF;
    }

    /**
     * Additive inverse in the additive group (mod 2^16).
     * Range [0, 0xFFFF].
     */
    private static int addInv(int a) {
        return (0x10000 - a) & 0xFFFF;
    }

    /**
     * Multiplication in the multiplicative group (mod 2^16+1 = mod 0x10001).
     * Range [0, 0xFFFF].
     */
    private static int mul(int a, int b) {
        long m = (long) a * b;
        if (m != 0) {
            return (int) (m % 0x10001) & 0xFFFF;
        } else {
            if (a != 0 || b != 0) {
                return (1 - a - b) & 0xFFFF;
            }
            return 1;
        }
    }

    /**
     * Multiplicative inverse in the multiplicative group (mod 2^16+1 = mod 0x10001).
     * It uses Extended Euclidean algorithm to compute the inverse.
     * For the purposes of IDEA, the all-zero sub-block is considered to represent 2^16 = −1
     * for multiplication modulo 216 + 1; thus the multiplicative inverse of 0 is 0.
     * Range [0, 0xFFFF].
     */
    private static int mulInv(int a) {
        if (a <= 1) {
            // 0 and 1 are their own inverses
            return a;
        }
        try {
            int b = 0x10001;
            int t0 = 1;
            int t1 = 0;
            while (true) {
                t1 += b / a * t0;
                b %= a;
                if (b == 1) {
                    return (1 - t1) & 0xffff;
                }
                t0 += a / b * t1;
                a %= b;
                if (a == 1) {
                    return t0;
                }
            }
        } catch (ArithmeticException e) {
            return 0;
        }
    }

}