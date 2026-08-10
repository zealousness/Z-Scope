package com.zscope.cli;

import java.nio.file.Files;
import java.nio.file.Paths;

public class Loader {
    public String read(String path) throws Exception {
        return Files.readString(Paths.get(path));
    }
}
