package com.zscope.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;

public class CryptoEntry {
    private static final String apiKey = "1234567890abcdef";

    public Cipher weakCipher() throws Exception {
        return Cipher.getInstance("DES/ECB/PKCS5Padding");
    }

    public IvParameterSpec fixedIv() {
        return new IvParameterSpec("1234567890123456".getBytes());
    }

    public long weakRandomToken() {
        return new Random().nextLong();
    }

    public void trustAllHostname(HttpsURLConnection connection) {
        HostnameVerifier verifier = (String host, SSLSession session) -> true;
        connection.setHostnameVerifier(verifier);
    }

    public String hardcodedSecret() {
        return apiKey;
    }

    public byte[] weakDigest(byte[] data) throws Exception {
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.setSeed(12345L);
        return MessageDigest.getInstance("MD5").digest(data);
    }
}
