package com.zscope.cli;

public class CliApp {
    public static void main(String[] args) throws Exception {
        new ProcessBuilder(args[0]).start();
    }
}
