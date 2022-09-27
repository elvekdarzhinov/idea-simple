package org.example;

import java.io.BufferedReader;
import java.io.FileReader;
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
             BufferedReader keyReader = new BufferedReader(new FileReader(KEY_FILE))) {

            byte[] input = inputReader.lines().collect(Collectors.joining()).getBytes(StandardCharsets.UTF_8);
            byte[] key = convertKey(keyReader.readLine());

            IdeaCipher ideaCipher = new IdeaCipher(key);

            byte[] encrypted = ideaCipher.crypt(input, true);
            byte[] decrypted = ideaCipher.crypt(encrypted, false);

            System.out.println(new String(input));
            System.out.println(new String(encrypted));
            System.out.println(new String(decrypted));

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