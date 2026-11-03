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
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.web.context.WebApplicationContext
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import org.slf4j.MDC
import spock.lang.Specification

/**
 * Integration tests for {@link ExternalAuthAutoConfiguration} using the dev method.
 */
class DevAuthAutoConfigurationTest extends Specification {

    // -------------------------------------------------------------------------
    // INSTANCE VARIABLES
    // -------------------------------------------------------------------------

    /** Runner configured with the starter in dev mode and an incomplete user (no names, groups, or roles). */
    final WebApplicationContextRunner baseRunner = new WebApplicationContextRunner()
    .withConfiguration(AutoConfigurations.of(
    ExternalAuthAutoConfiguration,
    SecurityAutoConfiguration,
    ServletWebSecurityAutoConfiguration))
    .withPropertyValues(
    "brightsparklabs.auth.method=dev",
    "brightsparklabs.auth.user.username=test.user",
    "brightsparklabs.auth.user.email=test.user@email.test")
    .withBean(RecordingAuthenticationEventListener, { new RecordingAuthenticationEventListener() })

    /** Runner configured with the starter in dev mode and a complete fixed user. */
    final WebApplicationContextRunner runner = baseRunner.withPropertyValues(
    "brightsparklabs.auth.user.first-name=Test",
    "brightsparklabs.auth.user.last-name=User",
    "brightsparklabs.auth.user.groups=GROUP_1",
    "brightsparklabs.auth.user.roles=ROLE_1",
    "brightsparklabs.auth.principal-field=email")
    .withUserConfiguration(MdcEchoController)

    // -------------------------------------------------------------------------
    // TESTS
    // -------------------------------------------------------------------------

    def "request without credentials is authenticated as configured user"() {
        expect:
        withMockMvc { mockMvc, listener ->
            mockMvc.perform(get("/"))
            assert listener.successes*.username() == ["test.user"]
        }
    }

    def "request without credentials is not rejected or redirected"() {
        expect:
        withMockMvc { mockMvc, listener ->
            final response = mockMvc.perform(get("/")).andReturn().response
            // No controller is mapped, so an authenticated request falls through to a 404.
            assert response.status == 404
        }
    }

    def "request adds configured user to MDC for the duration of the request"() {
        expect:
        withMockMvc { mockMvc, listener ->
            final response = mockMvc.perform(get(MdcEchoController.PATH)).andReturn().response
            assert response.contentAsString == "test.user@email.test"
        }
    }

    def "context with incomplete user fails to start"() {
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

    /** Echoes the MDC username observed while handling the request. */
    @RestController
    static class MdcEchoController {

        /** Path the controller is mapped to. */
        static final String PATH = "/mdc"

        /**
         * Returns the MDC username for the current request.
         *
         * @return The MDC username, or an empty string if absent.
         */
        @GetMapping(PATH)
        String mdcUsername() {
            return MDC.get("req.username") ?: ""
        }
    }
}
