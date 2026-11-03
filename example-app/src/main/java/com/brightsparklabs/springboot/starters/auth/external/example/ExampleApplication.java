/*
 * Maintained by brightSPARK Labs.
 * www.brightsparklabs.com
 *
 * Refer to LICENSE at repository root for license details.
 */

package com.brightsparklabs.springboot.starters.auth.external.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

/**
 * Example application used to exercise the external auth starter by hand.
 *
 * <p>Select the authentication setup via a Spring profile (for example {@code jwt-local} or {@code
 * jwt-keycloak}).
 *
 * @author brightSPARK Labs
 */
@SpringBootApplication
@EnableMethodSecurity
public class ExampleApplication {

    // -------------------------------------------------------------------------
    // PUBLIC METHODS
    // -------------------------------------------------------------------------

    /**
     * Entry point.
     *
     * @param args The command line arguments.
     */
    public static void main(final String[] args) {
        SpringApplication.run(ExampleApplication.class, args);
    }
}
