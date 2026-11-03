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
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.web.authentication.AuthenticationConverter
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.web.context.WebApplicationContext
import spock.lang.Specification

/**
 * Integration tests for {@link ExternalAuthAutoConfiguration} using the custom method, where the
 * consuming application supplies its own converter and provider.
 *
 * @author brightSPARK Labs
 */
class CustomAuthAutoConfigurationTest extends Specification {

    // -------------------------------------------------------------------------
    // CONSTANTS
    // -------------------------------------------------------------------------

    /** Header carrying the API key accepted by the custom provider. */
    static final String API_KEY_HEADER = "X-Api-Key"

    /** API key accepted by the custom provider. */
    static final String VALID_API_KEY = "valid-key"

    // -------------------------------------------------------------------------
    // INSTANCE VARIABLES
    // -------------------------------------------------------------------------

    /** Runner configured with the starter in custom mode, without any consumer beans. */
    final WebApplicationContextRunner baseRunner = new WebApplicationContextRunner()
    .withConfiguration(AutoConfigurations.of(
    ExternalAuthAutoConfiguration,
    SecurityAutoConfiguration,
    ServletWebSecurityAutoConfiguration))
    .withPropertyValues("brightsparklabs.auth.method=custom")

    /** Runner configured with the starter in custom mode, with the consumer beans. */
    final WebApplicationContextRunner runner = baseRunner
    .withUserConfiguration(ApiKeyAuthConfiguration)
    .withBean(RecordingAuthenticationEventListener, { new RecordingAuthenticationEventListener() })

    // -------------------------------------------------------------------------
    // TESTS
    // -------------------------------------------------------------------------

    def "request with valid credentials is authenticated by consumer provider"() {
        expect:
        withMockMvc { mockMvc, listener ->
            final response = mockMvc.perform(get("/").header(API_KEY_HEADER, VALID_API_KEY))
                    .andReturn()
                    .response
            // No controller is mapped, so an authenticated request falls through to a 404.
            assert response.status == 404
        }
    }

    def "request with invalid credentials responds 401"() {
        expect:
        withMockMvc { mockMvc, listener ->
            final response = mockMvc.perform(get("/").header(API_KEY_HEADER, "wrong-key"))
                    .andReturn()
                    .response
            assert response.status == 401
        }
    }

    def "request with valid credentials notifies listener of success"() {
        expect:
        withMockMvc { mockMvc, listener ->
            mockMvc.perform(get("/").header(API_KEY_HEADER, VALID_API_KEY))
            assert listener.successes*.username() == ["api.client"]
        }
    }

    def "context without consumer beans fails to start"() {
        expect:
        baseRunner.run { context ->
            assert context.startupFailure != null
        }
    }

    // -------------------------------------------------------------------------
    // PRIVATE METHODS
    // -------------------------------------------------------------------------

    /**
     * Runs the supplied assertions against the context.
     *
     * @param assertions Closure receiving a {@link MockMvc} wired with the security filter chain,
     *     and the registered listener.
     */
    private void withMockMvc(final Closure assertions) {
        runner.run { context ->
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

    /** Consumer configuration supplying an API key converter and provider. */
    @Configuration(proxyBeanMethods = false)
    static class ApiKeyAuthConfiguration {

        /**
         * Extracts the API key from each request.
         *
         * @return The converter.
         */
        @Bean
        AuthenticationConverter apiKeyAuthenticationConverter() {
            return { request ->
                new PreAuthenticatedAuthenticationToken("api-key", request.getHeader(API_KEY_HEADER) ?: "")
            } as AuthenticationConverter
        }

        /**
         * Accepts only the valid API key, authenticating it as a fixed client user.
         *
         * @param principalConverter Converter between {@link InternalUser} and the principal.
         * @return The provider.
         */
        @Bean
        AuthenticationProvider apiKeyAuthenticationProvider(
                final PrincipalConverter<?> principalConverter) {
            return new ExternalAuthenticationProvider(principalConverter) {
                        @Override
                        protected InternalUser doAuthenticate(final Object credentials)
                        throws AuthenticationDeniedException {
                            if (credentials != VALID_API_KEY) {
                                throw new AuthenticationDeniedException("Invalid API key.")
                            }
                            return new InternalUser(
                                    "api.client",
                                    "API",
                                    "Client",
                                    Optional.empty(),
                                    [] as Set,
                                    [] as Set,
                                    Optional.empty())
                        }
                    }
        }
    }
}
