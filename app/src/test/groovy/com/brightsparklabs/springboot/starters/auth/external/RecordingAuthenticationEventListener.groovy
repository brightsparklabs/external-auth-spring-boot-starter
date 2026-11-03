/*
 * Maintained by brightSPARK Labs.
 * www.brightsparklabs.com
 *
 * Refer to LICENSE at repository root for license details.
 */

package com.brightsparklabs.springboot.starters.auth.external

import org.springframework.core.Ordered
import org.springframework.security.authentication.AuthenticationServiceException

/**
 * Test helper which records every authentication event it is notified of.
 *
 * <p>Each notification is captured in the list for its event type, and a {@code <name>:<event>}
 * entry is appended to the call log. Sharing a call log between listeners allows tests to verify
 * the order in which listeners are notified.
 *
 * @author brightSPARK Labs
 */
class RecordingAuthenticationEventListener implements AuthenticationEventListener, Ordered {

    // -------------------------------------------------------------------------
    // CONSTANTS
    // -------------------------------------------------------------------------

    /** Name used in call log entries when none is supplied. */
    static final String DEFAULT_NAME = "listener"

    // -------------------------------------------------------------------------
    // INSTANCE VARIABLES
    // -------------------------------------------------------------------------

    /** Name used to prefix entries in the call log. */
    private final String name

    /** Order in which this listener is notified relative to other listeners. */
    private final int order

    /** Log of {@code <name>:<event>} entries, in notification order. */
    final List<String> callLog

    /** Users received via success notifications. */
    final List<InternalUser> successes = []

    /** Exceptions received via denial notifications. */
    final List<AuthenticationDeniedException> denials = []

    /** Exceptions received via error notifications. */
    final List<AuthenticationServiceException> errors = []

    // -------------------------------------------------------------------------
    // CONSTRUCTION
    // -------------------------------------------------------------------------

    /** Creates a listener with the default name, lowest precedence and its own call log. */
    RecordingAuthenticationEventListener() {
        this(DEFAULT_NAME, Ordered.LOWEST_PRECEDENCE, [])
    }

    /**
     * Creates a listener which appends to the supplied call log.
     *
     * @param name The name used to prefix entries in the call log.
     * @param order The order in which this listener is notified relative to other listeners.
     * @param callLog The call log to append entries to.
     */
    RecordingAuthenticationEventListener(final String name, final int order, final List<String> callLog) {
        this.name = name
        this.order = order
        this.callLog = callLog
    }

    // -------------------------------------------------------------------------
    // IMPLEMENTATION: AuthenticationEventListener
    // -------------------------------------------------------------------------

    @Override
    void onAuthenticationSuccess(final InternalUser authenticatedUser) {
        successes << authenticatedUser
        callLog << "${name}:success".toString()
    }

    @Override
    void onAuthenticationDenied(final AuthenticationDeniedException authDeniedException) {
        denials << authDeniedException
        callLog << "${name}:denied".toString()
    }

    @Override
    void onAuthenticationError(final AuthenticationServiceException authException) {
        errors << authException
        callLog << "${name}:error".toString()
    }

    // -------------------------------------------------------------------------
    // IMPLEMENTATION: Ordered
    // -------------------------------------------------------------------------

    @Override
    int getOrder() {
        return order
    }
}
