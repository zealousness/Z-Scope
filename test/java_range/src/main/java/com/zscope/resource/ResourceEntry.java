package com.zscope.resource;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.HashMap;
import java.util.Map;

import org.springframework.web.multipart.MultipartFile;

public class ResourceEntry {
    static HashMap<String, String> sharedCache = new HashMap<>();

    public int leakFile(String path) throws Exception {
        FileInputStream inputStream = new FileInputStream(path);
        return inputStream.read();
    }

    public byte[] readAll(MultipartFile file) throws Exception {
        var input = file.getInputStream();
        return input.readAllBytes();
    }

    public File tempFile(String name) throws Exception {
        File file = new File("/tmp/" + name);
        file.createNewFile();
        return file;
    }

    public void makeShared(Path path) throws Exception {
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwxrwxrwx"));
    }

    public Map<String, String> cache(String key, String value) {
        sharedCache.put(key, value);
        return sharedCache;
    }
}
