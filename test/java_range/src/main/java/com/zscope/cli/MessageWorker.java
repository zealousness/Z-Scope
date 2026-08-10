package com.zscope.cli;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import org.springframework.kafka.annotation.KafkaListener;

public class MessageWorker {
    @KafkaListener(topics = "jobs")
    public void onMessage(String payload) throws Exception {
        new ObjectInputStream(new ByteArrayInputStream(payload.getBytes())).readObject();
    }
}
