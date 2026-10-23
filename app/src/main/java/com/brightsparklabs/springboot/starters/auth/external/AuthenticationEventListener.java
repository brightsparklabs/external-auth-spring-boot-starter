/*
 * Maintained by brightSPARK Labs.
 * www.brightsparklabs.com
 *
 * Refer to LICENSE at repository root for license details.
 */

package com.brightsparklabs.springboot.starters.auth.external;

import org.springframework.security.authentication.AuthenticationServiceException;

/**
 * Interface for listeners to authentication events.
 *
 * <p>Register an implementation as a Spring bean (e.g. via {@code @Component} or a {@code @Bean}
 * method) and the starter will notify it of every authentication outcome via the {@link
 * AuthenticationEventListenerDispatcher}. Multiple listeners may be registered, and are notified in
 * {@code @Order} order.
 *
 * @author brightSPARK Labs
 */
public interface AuthenticationEventListener {

    /**
     * Listener function called on authentication success.
     *
     * @param authenticatedUser the successfully-authenticated user
     */
    default void onAuthenticationSuccess(final InternalUser authenticatedUser) {
        // Do nothing by default.
    }

    /**
     * Listener function called on authentication failure due to access being denied (e.g. invalid
     * or expired credentials).
     *
     * @param authDeniedException the exception describing why access was denied
     */
    default void onAuthenticationDenied(final AuthenticationDeniedException authDeniedException) {
        // Do nothing by default.
    }

    /**
     * Listener function called on authentication failure due to an error in the authentication
     * infrastructure (e.g. the identity provider being unreachable).
     *
     * @param authException the exception describing the error
     */
    default void onAuthenticationError(final AuthenticationServiceException authException) {
        // Do nothing by default.
    }
}
