package com.cht.fortify.audit;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class IssueSuppressorApplication {

    public static void main(String... args) {
        SpringApplication.run(IssueSuppressor.class, args);
    }

    @Bean
    public FvdlReader fvdlReader() {
        return new FvdlReader();
    }
}
