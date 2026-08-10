package com.zscope.cli;

public class EnvBatchJob {
    public void run() throws Exception {
        String cmd = System.getenv("JOB_CMD");
        Runtime.getRuntime().exec(cmd);
    }
}
