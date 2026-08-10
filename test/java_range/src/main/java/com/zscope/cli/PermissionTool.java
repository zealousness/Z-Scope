package com.zscope.cli;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

public class PermissionTool {
    public Path makeShared(String content) throws Exception {
        Path file = Files.createTempFile("zscope-perm", ".txt");
        Files.writeString(file, content);
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rwxrwxrwx"));
        return file;
    }
}
