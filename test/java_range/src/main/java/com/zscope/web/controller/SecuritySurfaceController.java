package com.zscope.web.controller;

import com.mongodb.client.MongoCollection;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.bson.Document;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/security")
public class SecuritySurfaceController {
    private static final Logger logger = LoggerFactory.getLogger(SecuritySurfaceController.class);

    @GetMapping("/headers")
    public void writeHeader(HttpServletResponse response, @RequestParam String value) {
        response.setHeader("X-ZScope", value);
    }

    @GetMapping("/cookie")
    public void cookie(HttpServletResponse response, @RequestParam String sid) {
        response.addCookie(new Cookie("sid", sid));
    }

    @CrossOrigin("*")
    @GetMapping("/cors")
    public String cors(@RequestParam String name) {
        return name;
    }

    @GetMapping("/log")
    public void logToken(@RequestHeader("Authorization") String authorization) {
        logger.info("authorization=" + authorization);
    }

    @GetMapping("/xss/reflected")
    public String reflectedXss(@RequestParam String payload) {
        return payload;
    }

    @GetMapping("/xss/stored")
    public String storedXss(
        MongoCollection<Document> collection,
        @RequestParam String payload,
        @RequestHeader("User-Agent") String userAgent
    ) {
        collection.insertOne(new Document("payload", payload).append("ua", userAgent));
        return "ok";
    }

    @GetMapping("/xss/template")
    public String templateXss(@RequestParam String payload, Model model) {
        model.addAttribute("html", payload);
        return "view";
    }
}
