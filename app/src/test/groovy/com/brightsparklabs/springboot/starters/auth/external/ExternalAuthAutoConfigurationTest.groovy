/*
 * Maintained by brightSPARK Labs.
 * www.brightsparklabs.com
 *
 * Refer to LICENSE at repository root for license details.
 */

package com.brightsparklabs.springboot.starters.auth.external

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get

import org.springframework.boot.autoconfigure.AutoConfigurations
import org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration
import org.springframework.boot.test.context.runner.WebApplicationContextRunner
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.oauth2.jwt.BadJwtException
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtException
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.web.context.WebApplicationContext
import spock.lang.Specification

/**
 * Integration tests for {@link ExternalAuthAutoConfiguration} using the JWT method, verifying that
 * authentication outcomes reach registered {@link AuthenticationEventListener} beans.
 */
class ExternalAuthAutoConfigurationTest extends Specification {

    // -------------------------------------------------------------------------
    // CONSTANTS
    // -------------------------------------------------------------------------

    /** Token which the stub decoder accepts. */
    static final String VALID_TOKEN = "valid"

    /** Token which the stub decoder rejects as invalid. */
    static final String INVALID_TOKEN = "invalid"

    /** Token which causes the stub decoder to fail as though the identity provider is down. */
    static final String ERROR_TOKEN = "error"

    // -------------------------------------------------------------------------
    // INSTANCE VARIABLES
    // -------------------------------------------------------------------------

    /** Runner configured with the starter and Spring Boot's security auto-configuration. */
    final WebApplicationContextRunner runner = new WebApplicationContextRunner()
    .withConfiguration(AutoConfigurations.of(
    ExternalAuthAutoConfiguration,
    SecurityAutoConfiguration,
    ServletWebSecurityAutoConfiguration))
    .withPropertyValues("brightsparklabs.auth.method=jwt")
    .withUserConfiguration(StubJwtDecoderConfiguration)

    // -------------------------------------------------------------------------
    // TESTS
    // -------------------------------------------------------------------------

    def "context with no listeners starts"() {
        expect:
        runner.run { context ->
            assert context.startupFailure == null
        }
    }

    def "context registers dispatcher bean"() {
        expect:
        runner.run { context ->
            assert context.getBeansOfType(AuthenticationEventListenerDispatcher).size() == 1
        }
    }

    def "request with valid token notifies listener of success"() {
        expect:
        withListener { mockMvc, listener ->
            mockMvc.perform(get("/").header("Authorization", "Bearer ${VALID_TOKEN}"))
            assert listener.successes*.username() == ["alice"]
        }
    }

    def "request with invalid token notifies listener of denial"() {
        expect:
        withListener { mockMvc, listener ->
            mockMvc.perform(get("/").header("Authorization", "Bearer ${INVALID_TOKEN}"))
            assert listener.callLog == ["listener:denied"]
        }
    }

    def "request with invalid token responds 401"() {
        expect:
        withListener { mockMvc, listener ->
            final response = mockMvc
                    .perform(get("/").header("Authorization", "Bearer ${INVALID_TOKEN}"))
                    .andReturn()
                    .response
            assert response.status == 401
        }
    }

    def "request with identity provider failure notifies listener of error"() {
        expect:
        withListener { mockMvc, listener ->
            /* Spring Security deliberately rethrows service exceptions from the bearer token
             * filter (surfacing as a server error), so tolerate it and check the listener.
             */
            try {
                mockMvc.perform(get("/").header("Authorization", "Bearer ${ERROR_TOKEN}"))
            } catch (final Exception ignored) {
                // Expected.
            }
            assert listener.callLog == ["listener:error"]
        }
    }

    // -------------------------------------------------------------------------
    // PRIVATE METHODS
    // -------------------------------------------------------------------------

    /**
     * Runs the supplied assertions against a context with a recording listener registered.
     *
     * @param assertions Closure receiving a {@link MockMvc} wired with the security filter chain,
     *     and the registered listener.
     */
    private void withListener(final Closure assertions) {
        runner.withBean(RecordingAuthenticationEventListener, { new RecordingAuthenticationEventListener() })
        .run { context ->
            assert context.startupFailure == null
            final MockMvc mockMvc = MockMvcBuilders
                    .webAppContextSetup(context as WebApplicationContext)
                    .apply(springSecurity())
                    .build()
            assertions.call(mockMvc, context.getBean(RecordingAuthenticationEventListener))
        }
    }

    // -------------------------------------------------------------------------
    // INNER CLASSES
    // -------------------------------------------------------------------------

    /** Supplies a decoder which maps fixed token values to fixed outcomes. */
    @Configuration(proxyBeanMethods = false)
    static class StubJwtDecoderConfiguration {

        /**
         * Creates the stub decoder.
         *
         * @return The stub decoder.
         */
        @Bean
        JwtDecoder jwtDecoder() {
            return { String token ->
                switch (token) {
                    case VALID_TOKEN:
                        return Jwt.withTokenValue(token)
                        .header("alg", "none")
                        .issuer("https://idp.example.com/realms/test")
                        .claim(JwtClaimsAuthenticationConverter.CLAIM_FIELD_USERNAME, "alice")
                        .claim(JwtClaimsAuthenticationConverter.CLAIM_FIELD_FIRSTNAME, "Alice")
                        .claim(JwtClaimsAuthenticationConverter.CLAIM_FIELD_LASTNAME, "Smith")
                        .claim(JwtClaimsAuthenticationConverter.CLAIM_FIELD_EMAIL, "alice@example.com")
                        .build()
                    case INVALID_TOKEN:
                        throw new BadJwtException("Signature invalid.")
                    default:
                        throw new JwtException("Identity provider unreachable.")
                }
            } as JwtDecoder
        }
    }
}
