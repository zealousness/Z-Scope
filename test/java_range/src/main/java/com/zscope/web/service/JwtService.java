package com.zscope.web.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.stereotype.Service;

@Service
public class JwtService {
    public String issueToken(String subject) {
        Algorithm algorithm = Algorithm.HMAC256("hardcoded-benchmark-secret");
        return JWT.create().withSubject(subject).sign(algorithm);
    }

    public String decodeWithoutVerification(String token) {
        return JWT.decode(token).getSubject();
    }
}
