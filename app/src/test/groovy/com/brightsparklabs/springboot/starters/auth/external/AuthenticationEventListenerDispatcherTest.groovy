/*
 * Maintained by brightSPARK Labs.
 * www.brightsparklabs.com
 *
 * Refer to LICENSE at repository root for license details.
 */

package com.brightsparklabs.springboot.starters.auth.external

import org.springframework.beans.factory.support.DefaultListableBeanFactory
import org.springframework.security.authentication.AuthenticationServiceException
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent
import org.springframework.security.authentication.event.AuthenticationFailureServiceExceptionEvent
import org.springframework.security.authentication.event.AuthenticationSuccessEvent
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken
import spock.lang.Specification

/**
 * Unit tests for {@link AuthenticationEventListenerDispatcher}.
 */
class AuthenticationEventListenerDispatcherTest extends Specification {

    // -------------------------------------------------------------------------
    // CONSTANTS
    // -------------------------------------------------------------------------

    /** User authenticated by the tests. */
    static final InternalUser USER = new InternalUser(
    "jsmith",
    "John",
    "Smith",
    Optional.of("john.smith@example.com"),
    [] as Set,
    [] as Set,
    Optional.empty())

    /** Authentication request used for failure events. */
    static final PreAuthenticatedAuthenticationToken REQUEST =
    new PreAuthenticatedAuthenticationToken("anonymous", "credential")

    // -------------------------------------------------------------------------
    // TESTS
    // -------------------------------------------------------------------------

    def "onSuccess with converted principal notifies listener with user"() {
        given:
        final listener = new RecordingAuthenticationEventListener()
        final dispatcher = dispatcherFor(listener)

        when:
        dispatcher.onSuccess(new AuthenticationSuccessEvent(authenticated(USER)))

        then:
        listener.successes == [USER]
    }

    def "onSuccess with principal of unexpected type does not notify listener"() {
        given:
        final listener = new RecordingAuthenticationEventListener()
        final dispatcher = dispatcherFor(listener)

        when:
        dispatcher.onSuccess(new AuthenticationSuccessEvent(authenticated("not-an-internal-user")))

        then:
        listener.callLog.isEmpty()
    }

    def "onFailure with bad credentials notifies listener of denial with original cause"() {
        given:
        final listener = new RecordingAuthenticationEventListener()
        final dispatcher = dispatcherFor(listener)
        final cause = new BadCredentialsException("bad token")

        when:
        dispatcher.onFailure(new AuthenticationFailureBadCredentialsEvent(REQUEST, cause))

        then:
        listener.denials*.cause == [cause]
    }

    def "onFailure with wrapped denied exception notifies listener with original denial"() {
        given:
        final listener = new RecordingAuthenticationEventListener()
        final dispatcher = dispatcherFor(listener)
        final original = new AuthenticationDeniedException("not allowed")

        when:
        dispatcher.onFailure(new AuthenticationFailureBadCredentialsEvent(
                REQUEST, new BadCredentialsException("not allowed", original)))

        then:
        listener.denials == [original]
    }

    def "onFailure with service exception notifies listener of error"() {
        given:
        final listener = new RecordingAuthenticationEventListener()
        final dispatcher = dispatcherFor(listener)
        final error = new AuthenticationServiceException("idp unreachable")

        when:
        dispatcher.onFailure(new AuthenticationFailureServiceExceptionEvent(REQUEST, error))

        then:
        listener.errors == [error]
    }

    def "onFailure with service exception does not notify listener of denial"() {
        given:
        final listener = new RecordingAuthenticationEventListener()
        final dispatcher = dispatcherFor(listener)

        when:
        dispatcher.onFailure(new AuthenticationFailureServiceExceptionEvent(
                REQUEST, new AuthenticationServiceException("idp unreachable")))

        then:
        listener.denials.isEmpty()
    }

    def "onSuccess with no listeners does not throw"() {
        given:
        final dispatcher = dispatcherFor()

        when:
        dispatcher.onSuccess(new AuthenticationSuccessEvent(authenticated(USER)))

        then:
        noExceptionThrown()
    }

    def "onSuccess with multiple listeners notifies them in order"() {
        given:
        final callLog = []
        final dispatcher = dispatcherFor(
                new RecordingAuthenticationEventListener("second", 2, callLog),
                new RecordingAuthenticationEventListener("first", 1, callLog))

        when:
        dispatcher.onSuccess(new AuthenticationSuccessEvent(authenticated(USER)))

        then:
        callLog == [
            "first:success",
            "second:success"
        ]
    }

    // -------------------------------------------------------------------------
    // PRIVATE METHODS
    // -------------------------------------------------------------------------

    /**
     * Creates a dispatcher, backed by the identity converter, over the supplied listeners.
     *
     * @param listeners The listeners to register.
     * @return The dispatcher.
     */
    private static AuthenticationEventListenerDispatcher dispatcherFor(
            final AuthenticationEventListener... listeners) {
        final beanFactory = new DefaultListableBeanFactory()
        listeners.eachWithIndex { listener, index ->
            beanFactory.registerSingleton("listener${index}", listener)
        }
        return new AuthenticationEventListenerDispatcher(
                beanFactory.getBeanProvider(AuthenticationEventListener),
                new IdentityPrincipalConverter())
    }

    /**
     * Creates an authenticated token holding the supplied principal.
     *
     * @param principal The principal to authenticate with.
     * @return The authenticated token.
     */
    private static PreAuthenticatedAuthenticationToken authenticated(final Object principal) {
        return new PreAuthenticatedAuthenticationToken(principal, "credential", [])
    }
}
