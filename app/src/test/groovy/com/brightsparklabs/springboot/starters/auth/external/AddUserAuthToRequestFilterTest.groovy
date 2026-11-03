/*
 * Maintained by brightSPARK Labs.
 * www.brightsparklabs.com
 *
 * Refer to LICENSE at repository root for license details.
 */

package com.brightsparklabs.springboot.starters.auth.external

import com.brightsparklabs.springboot.starters.auth.external.ExternallyAuthenticatedAuthStarterConfiguration.MdcPrincipalUsernameField
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.MDC
import org.springframework.security.authentication.AnonymousAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken
import spock.lang.Specification

/**
 * Unit tests for {@link AddUserAuthToRequestFilter}.
 */
class AddUserAuthToRequestFilterTest extends Specification {

    // -------------------------------------------------------------------------
    // CONSTANTS
    // -------------------------------------------------------------------------

    /** MDC key used by the filter under test. */
    static final String MDC_KEY = "req.username"

    /** User placed into the security context by the tests. */
    static final InternalUser USER = new InternalUser(
    "jsmith",
    "John",
    "Smith",
    Optional.of("john.smith@example.com"),
    [] as Set,
    [] as Set,
    Optional.empty())

    // -------------------------------------------------------------------------
    // INSTANCE VARIABLES
    // -------------------------------------------------------------------------

    /** Value of the MDC key observed while the rest of the chain was running. */
    String mdcValueDuringChain

    /** Chain that records the MDC value it observes. */
    FilterChain filterChain = { request, response ->
        mdcValueDuringChain = MDC.get(MDC_KEY)
    } as FilterChain

    // -------------------------------------------------------------------------
    // FIXTURE METHODS
    // -------------------------------------------------------------------------

    def cleanup() {
        SecurityContextHolder.clearContext()
        MDC.clear()
    }

    // -------------------------------------------------------------------------
    // TESTS
    // -------------------------------------------------------------------------

    def "doFilterInternal with converted principal adds username to MDC during chain"() {
        given:
        authenticateWith(USER)

        when:
        runFilter(MdcPrincipalUsernameField.USERNAME)

        then:
        mdcValueDuringChain == "jsmith"
    }

    def "doFilterInternal with email principal field adds email to MDC during chain"() {
        given:
        authenticateWith(USER)

        when:
        runFilter(MdcPrincipalUsernameField.EMAIL)

        then:
        mdcValueDuringChain == "john.smith@example.com"
    }

    def "doFilterInternal with converted principal clears MDC after chain"() {
        given:
        authenticateWith(USER)

        when:
        runFilter(MdcPrincipalUsernameField.USERNAME)

        then:
        MDC.get(MDC_KEY) == null
    }

    def "doFilterInternal with principal of unexpected type does not add to MDC"() {
        given:
        authenticateWith("not-an-internal-user")

        when:
        runFilter(MdcPrincipalUsernameField.USERNAME)

        then:
        mdcValueDuringChain == null
    }

    def "doFilterInternal with anonymous authentication does not add to MDC"() {
        given:
        SecurityContextHolder.getContext().setAuthentication(
                new AnonymousAuthenticationToken(
                "key", "anonymousUser", [
                    new SimpleGrantedAuthority("ROLE_ANONYMOUS")
                ]))

        when:
        runFilter(MdcPrincipalUsernameField.USERNAME)

        then:
        mdcValueDuringChain == null
    }

    def "doFilterInternal with no authentication does not add to MDC"() {
        when:
        runFilter(MdcPrincipalUsernameField.USERNAME)

        then:
        mdcValueDuringChain == null
    }

    // -------------------------------------------------------------------------
    // PRIVATE METHODS
    // -------------------------------------------------------------------------

    /**
     * Places an authenticated token holding the supplied principal into the security context.
     *
     * @param principal The principal to authenticate with.
     */
    private static void authenticateWith(final Object principal) {
        SecurityContextHolder.getContext().setAuthentication(
                new PreAuthenticatedAuthenticationToken(principal, "credential", []))
    }

    /**
     * Runs a new filter, backed by the identity converter, over a stub request.
     *
     * <p>Invokes {@code doFilterInternal} directly, as the once-per-request bookkeeping in {@code
     * doFilter} belongs to Spring rather than the behaviour under test.
     *
     * @param principalField The field of the user to place into the MDC.
     */
    private void runFilter(final MdcPrincipalUsernameField principalField) {
        final filter = new AddUserAuthToRequestFilter<InternalUser>(
                new IdentityPrincipalConverter(), MDC_KEY, principalField)
        filter.doFilterInternal(
                [:] as HttpServletRequest, [:] as HttpServletResponse, filterChain)
    }
}
