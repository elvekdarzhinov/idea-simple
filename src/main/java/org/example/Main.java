package org.example;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

public class Main {
    private static final String KEY_FILE = "key.txt";
    private static final String INPUT_FILE = "input.txt";
    private static final String ENCRYPTED_FILE = "encrypted.txt";
    private static final String DECRYPTED_FILE = "decrypted.txt";

    public static void main(String[] args) {
        try (BufferedReader inputReader = new BufferedReader(new FileReader(INPUT_FILE));
             BufferedReader keyReader = new BufferedReader(new FileReader(KEY_FILE));
             BufferedWriter encryptedWriter = new BufferedWriter(new FileWriter(ENCRYPTED_FILE));
             BufferedWriter decryptedWriter = new BufferedWriter(new FileWriter(DECRYPTED_FILE))) {

            byte[] input = inputReader.lines().collect(Collectors.joining()).getBytes(StandardCharsets.UTF_8);
            byte[] key = convertKey(keyReader.readLine());

            IdeaCipher ideaCipher = new IdeaCipher(key);

            for (int i = 0; i < input.length; i += IdeaCipher.BLOCK_SIZE) {
                byte[] encrypted = ideaCipher.crypt(input, i, true);
                encryptedWriter.write(new String(encrypted));

                byte[] decrypted = ideaCipher.crypt(encrypted, 0, false);
                decryptedWriter.write(new String(decrypted));
            }


        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] convertKey(String keyString) {
        String[] bytes = keyString.split(" ");
        byte[] key = new byte[bytes.length];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) Integer.parseInt(bytes[i], 16);
        }
        return key;
    }

}