/*
 * Maintained by brightSPARK Labs.
 * www.brightsparklabs.com
 *
 * Refer to LICENSE at repository root for license details.
 */

package com.brightsparklabs.springboot.starters.auth.external

import com.brightsparklabs.springboot.starters.auth.external.ExternallyAuthenticatedAuthStarterConfiguration.HttpHeadersConfiguration
import org.springframework.mock.web.MockHttpServletRequest
import spock.lang.Specification

/**
 * Unit tests for {@link HeaderFieldsAuthenticationConverter}.
 *
 * @author brightSPARK Labs
 */
class HeaderFieldsAuthenticationConverterTest extends Specification {

    // -------------------------------------------------------------------------
    // INSTANCE VARIABLES
    // -------------------------------------------------------------------------

    /** Converter under test, using the default header names. */
    final HeaderFieldsAuthenticationConverter converter =
    new HeaderFieldsAuthenticationConverter(HttpHeadersConfiguration.DEFAULT_INSTANCE)

    // -------------------------------------------------------------------------
    // TESTS
    // -------------------------------------------------------------------------

    def "convert with identity and other headers collects only identity headers keyed in lower case"() {
        given:
        final request = new MockHttpServletRequest()
        request.addHeader("X-Auth-Username", "first.last")
        request.addHeader("Authorization", "Bearer secret")
        request.addHeader("Cookie", "SESSION=secret")
        request.addHeader("Accept", "application/json")

        when:
        final result = converter.convert(request)

        then:
        result.credentials.keySet() == ["x-auth-username"] as Set
    }

    def "convert with upper-case identity header collects it keyed in lower case"() {
        given:
        final request = new MockHttpServletRequest()
        request.addHeader("X-AUTH-USERNAME", "first.last")

        when:
        final result = converter.convert(request)

        then:
        result.credentials.get("x-auth-username") == ["first.last"]
    }

    def "convert with repeated identity header keeps values in order received"() {
        given:
        final request = new MockHttpServletRequest()
        request.addHeader("X-Auth-Groups", "g2")
        request.addHeader("X-Auth-Groups", "g1")
        request.addHeader("X-Auth-Groups", "g2")

        when:
        final result = converter.convert(request)

        then:
        result.credentials.get("x-auth-groups") == ["g2", "g1", "g2"]
    }

    def "convert with only sensitive headers does not expose them in token"() {
        given:
        final request = new MockHttpServletRequest()
        request.addHeader("Authorization", "Bearer secret")

        when:
        final result = converter.convert(request)

        then:
        !result.toString().contains("secret")
    }
}
