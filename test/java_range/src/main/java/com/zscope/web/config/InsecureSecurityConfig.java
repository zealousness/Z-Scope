package com.zscope.web.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class InsecureSecurityConfig {
    private static final String DRUID_MONITOR_MAPPING = "/druid/*";
    private static final String DRUID_MONITOR_SERVLET = "StatViewServlet";

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        String exposedMonitor = DRUID_MONITOR_SERVLET + ":" + DRUID_MONITOR_MAPPING;
        return http.csrf().disable()
            .authorizeHttpRequests(auth -> auth.requestMatchers("/**").permitAll())
            .build();
    }
}
