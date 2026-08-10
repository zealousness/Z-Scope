package com.zscope.cli;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Scanner;

public class StdinTool {
    public String readFromStdin() throws Exception {
        String path = new Scanner(System.in).nextLine();
        return Files.readString(Paths.get(path));
    }
}
