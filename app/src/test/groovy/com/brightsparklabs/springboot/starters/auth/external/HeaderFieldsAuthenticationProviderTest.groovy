/*
 * Maintained by brightSPARK Labs.
 * www.brightsparklabs.com
 *
 * Refer to LICENSE at repository root for license details.
 */

package com.brightsparklabs.springboot.starters.auth.external

import com.brightsparklabs.springboot.starters.auth.external.ExternallyAuthenticatedAuthStarterConfiguration.HttpHeadersConfiguration
import com.google.common.collect.ArrayListMultimap
import com.google.common.collect.Multimap
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken
import spock.lang.Specification

/**
 * Unit tests for {@link HeaderFieldsAuthenticationProvider}.
 *
 * <p>Authentication requests are built by passing a mock HTTP request through the real {@link
 * HeaderFieldsAuthenticationConverter}, as the provider relies on the converter having normalised
 * the header names to lower case.
 *
 * <p>Listener notification is not tested here, as it is performed by the {@link
 * AuthenticationEventListenerDispatcher} rather than the provider.
 *
 * @author brightSPARK Labs
 */
class HeaderFieldsAuthenticationProviderTest extends Specification {

    // -------------------------------------------------------------------------
    // CONSTANTS
    // -------------------------------------------------------------------------

    /** Converter used to build authentication requests, using the default header names. */
    static final HeaderFieldsAuthenticationConverter CONVERTER =
    new HeaderFieldsAuthenticationConverter(HttpHeadersConfiguration.DEFAULT_INSTANCE)

    // -------------------------------------------------------------------------
    // INSTANCE VARIABLES
    // -------------------------------------------------------------------------

    /** Provider under test, using the default header names. */
    final HeaderFieldsAuthenticationProvider provider = new HeaderFieldsAuthenticationProvider(
    new IdentityPrincipalConverter(), HttpHeadersConfiguration.DEFAULT_INSTANCE)

    // -------------------------------------------------------------------------
    // TESTS
    // -------------------------------------------------------------------------

    def "authenticate with all fields returns user with groups and roles split on commas"() {
        given:
        final headers = createHeaders("first.last", "first", "last", "first.last@email.com", groups, roles)

        when:
        final result = provider.authenticate(tokenFor(headers))

        then:
        result.principal == new InternalUser(
                "first.last",
                "first",
                "last",
                Optional.of("first.last@email.com"),
                expectedGroups as Set,
                expectedRoles as Set,
                Optional.empty())

        where:
        groups              | roles                 | expectedGroups       | expectedRoles
        "g1,g2,g3"          | "r1,r2,r3"            | ["g1", "g2", "g3"]   | ["r1", "r2", "r3"]
        " ,  g1,  g2,   g3" | "  r1,   r2,   r3,, " | ["g1", "g2", "g3"]   | ["r1", "r2", "r3"]
        null                | "  r1,   r2,   r3,, " | []                   | ["r1", "r2", "r3"]
        " ,  g1,  g2,   g3" | null                  | ["g1", "g2", "g3"]   | []
        null                | null                  | []                   | []
    }

    def "authenticate without email returns user with empty email"() {
        given:
        final headers = createHeaders("first.last", "first", "last", null, null, null)

        when:
        final result = provider.authenticate(tokenFor(headers))

        then:
        result.principal.email() == Optional.empty()
    }

    def "authenticate without #missingField throws bad credentials"() {
        given:
        final headers = createHeaders(username, firstName, lastName, "first.last@email.com", null, null)

        when:
        provider.authenticate(tokenFor(headers))

        then:
        thrown(BadCredentialsException)

        where:
        missingField | username     | firstName | lastName
        "username"   | null         | "first"   | "last"
        "first name" | "first.last" | null      | "last"
        "last name"  | "first.last" | "first"   | null
    }

    def "authenticate with empty required value throws bad credentials"() {
        given:
        final headers = createHeaders("", "first", "last", null, null, null)

        when:
        provider.authenticate(tokenFor(headers))

        then:
        thrown(BadCredentialsException)
    }

    def "authenticate without headers throws bad credentials"() {
        when:
        provider.authenticate(new PreAuthenticatedAuthenticationToken("anonymous", null))

        then:
        thrown(BadCredentialsException)
    }

    def "authenticate with multiple candidate headers uses highest priority header"() {
        given:
        final headers = createHeaders("low.priority", "first", "last", null, null, null)
        headers.put("X-Auth-Request-Preferred-Username", "high.priority")

        when:
        final result = provider.authenticate(tokenFor(headers))

        then:
        result.principal.username() == "high.priority"
    }

    def "authenticate with #description header names matches configured names"() {
        given:
        final Multimap<String, String> headers = ArrayListMultimap.create()
        createHeaders("first.last", "first", "last", "first.last@email.com", "g1", "r1")
                .entries()
                .each { headers.put(transform(it.key), it.value) }

        when:
        final result = provider.authenticate(tokenFor(headers))

        then:
        result.principal == new InternalUser(
                "first.last",
                "first",
                "last",
                Optional.of("first.last@email.com"),
                ["g1"] as Set,
                ["r1"] as Set,
                Optional.empty())

        where:
        description  | transform
        "lower-case" | { String name -> name.toLowerCase(Locale.ROOT) }
        "upper-case" | { String name -> name.toUpperCase(Locale.ROOT) }
    }

    def "authenticate with repeated header differing only in case merges values"() {
        given:
        final headers = createHeaders("first.last", "first", "last", null, "g1", null)
        headers.put("x-auth-groups", "g2")

        when:
        final result = provider.authenticate(tokenFor(headers))

        then:
        result.principal.groups() == ["g1", "g2"] as Set
    }

    // -------------------------------------------------------------------------
    // FIXTURES
    // -------------------------------------------------------------------------

    /**
     * Creates request headers using the lowest-priority default header names, omitting any field
     * which is {@code null}.
     *
     * @param username Username header value.
     * @param firstName First name header value.
     * @param lastName Last name header value.
     * @param email Email header value.
     * @param groups Comma-separated groups header value.
     * @param roles Comma-separated roles header value.
     * @return The headers, as produced by {@link HeaderFieldsAuthenticationConverter}.
     */
    private static Multimap<String, String> createHeaders(
            final String username,
            final String firstName,
            final String lastName,
            final String email,
            final String groups,
            final String roles) {
        final Multimap<String, String> headers = ArrayListMultimap.create()
        if (username != null) headers.put("X-Auth-Username", username)
        if (firstName != null) headers.put("X-Auth-Given-Name", firstName)
        if (lastName != null) headers.put("X-Auth-Family-Name", lastName)
        if (email != null) headers.put("X-Auth-Email", email)
        if (groups != null) headers.put("X-Auth-Groups", groups)
        if (roles != null) headers.put("X-Auth-Roles", roles)
        return headers
    }

    /**
     * Builds the unauthenticated token for a request carrying the supplied headers, by passing it
     * through the real {@link HeaderFieldsAuthenticationConverter}.
     *
     * @param headers The request headers.
     * @return The unauthenticated token produced by the converter.
     */
    private static Authentication tokenFor(final Multimap<String, String> headers) {
        final request = new MockHttpServletRequest()
        headers.entries().each { request.addHeader(it.key, it.value) }
        return CONVERTER.convert(request)
    }
}
