/*
 * Maintained by brightSPARK Labs.
 * www.brightsparklabs.com
 *
 * Refer to LICENSE at repository root for license details.
 */

package com.brightsparklabs.springboot.starters.auth.external;

import static java.util.Objects.requireNonNull;

import java.util.Optional;
import java.util.function.Consumer;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.event.EventListener;
import org.springframework.core.Ordered;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationFailureServiceExceptionEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.AuthenticationException;

// spotless:off - NOTE: Spotless does not support {@snippet} annotations.
/**
 * Bridges Spring Security's authentication events to the {@link AuthenticationEventListener} beans
 * registered by consumers.
 *
 * <p>Every authentication method (JWT, HTTP headers, dev) authenticates through a Spring Security
 * {@code ProviderManager}, which publishes an event for each outcome. Dispatching from those events
 * means listeners are notified consistently regardless of the method in use, without each method
 * needing to thread the listeners through its own code.
 *
 * <p>Without this dispatcher, the listener calls would need to be inserted within the various
 * security beans themselves. E.g.
 *
 * {@snippet lang=java :
 *       @Bean
 *       public SecurityFilterChain jwtSecurityFilterChain(
 *             final HttpSecurity http,
 *             final ObjectProvider<AuthenticationEventListener> listeners)
 *             throws Exception {
 *
 *         http
 *          // Mixed in with your other HTTP Security configuration options.
 *          // The success handler needs to be repeated in the provider(s).
 *          ...
 *          .exceptionHandling(
 *                 e ->
 *                         e.authenticationEntryPoint(
 *                                 (_, _, ex) -> {
 *                                     if (ex instanceof AuthenticationServiceException) {
 *                                         // Error caused by an authentication service
 *                                         // (E.g. LDAP server is down)
 *                                         listeners.foreach(
 *                                                 listener -> listener.onAuthenticationError(ex));
 *                                     } else {
 *                                         // All other exceptions are some form of
 *                                         // authentication denied.
 *                                         listeners.foreach(
 *                                                 listener -> listener.onAuthenticationDenied(ex));
 *                                     }
 *                                 }));
 *
 *         return http.build();
 *        }
 * }
 *
 * <p>Events are mapped as follows:
 *
 * <ul>
 *   <li>{@link AuthenticationSuccessEvent} to {@link
 *       AuthenticationEventListener#onAuthenticationSuccess}.
 *   <li>{@link AuthenticationFailureServiceExceptionEvent} to {@link
 *       AuthenticationEventListener#onAuthenticationError}.
 *   <li>Any other {@link AbstractAuthenticationFailureEvent} to {@link
 *       AuthenticationEventListener#onAuthenticationDenied}.
 * </ul>
 *
 * @author brightSPARK Labs
 */
// spotless:on - NOTE: Spotless does not support {@snippet} annotations.
public final class AuthenticationEventListenerDispatcher {

    // -------------------------------------------------------------------------
    // INSTANCE VARIABLES
    // -------------------------------------------------------------------------

    /**
     * Supplies the registered listeners, in {@link Ordered} order (i.e. the order in which they are
     * defined, or otherwise ordered using the Spring Boot {@code @Ordered} interface).
     */
    private final ObjectProvider<AuthenticationEventListener> listeners;

    /** Converts the system principal back to an {@link InternalUser}. */
    private final PrincipalConverter<?> principalConverter;

    // -------------------------------------------------------------------------
    // CONSTRUCTION
    // -------------------------------------------------------------------------

    /**
     * Creates a new dispatcher.
     *
     * @param listeners Supplies the registered listeners. May supply none.
     * @param principalConverter Converts the system principal back to an {@link InternalUser}.
     */
    public AuthenticationEventListenerDispatcher(
            final ObjectProvider<AuthenticationEventListener> listeners,
            final PrincipalConverter<?> principalConverter) {
        this.listeners = requireNonNull(listeners);
        this.principalConverter = requireNonNull(principalConverter);
    }

    // -------------------------------------------------------------------------
    // PUBLIC METHODS
    // -------------------------------------------------------------------------

    /**
     * Notifies listeners of a successful authentication.
     *
     * <p>Authentications whose principal cannot be converted to an {@link InternalUser} (e.g. those
     * performed by other providers in the consuming application) are ignored.
     *
     * @param event The success event published by Spring Security.
     */
    @EventListener
    public void onSuccess(final AuthenticationSuccessEvent event) {
        final Optional<InternalUser> user =
                principalConverter.toInternalUser(event.getAuthentication().getPrincipal());
        user.ifPresent(u -> notifyListeners(listener -> listener.onAuthenticationSuccess(u)));
    }

    /**
     * Notifies listeners of a failed authentication.
     *
     * <p>Infrastructure failures are reported as errors; all other failures are reported as
     * denials.
     *
     * @param event The failure event published by Spring Security.
     */
    @EventListener
    public void onFailure(final AbstractAuthenticationFailureEvent event) {
        final AuthenticationException exception = event.getException();
        if (event instanceof AuthenticationFailureServiceExceptionEvent
                && exception instanceof AuthenticationServiceException serviceException) {
            notifyListeners(listener -> listener.onAuthenticationError(serviceException));
            return;
        }

        final AuthenticationDeniedException denied = toDeniedException(exception);
        notifyListeners(listener -> listener.onAuthenticationDenied(denied));
    }

    // -------------------------------------------------------------------------
    // PRIVATE METHODS
    // -------------------------------------------------------------------------

    /**
     * Invokes the supplied action against each registered listener, in order.
     *
     * @param action The action to invoke.
     */
    private void notifyListeners(final Consumer<AuthenticationEventListener> action) {
        listeners.orderedStream().forEach(action);
    }

    /**
     * Converts a Spring authentication exception into the denied exception exposed to listeners.
     *
     * <p>If the exception wraps an original {@link AuthenticationDeniedException} (as thrown by an
     * {@link ExternalAuthenticationProvider}), that original is unwrapped so listeners see the
     * authenticator's own reason. This prevents the listener from needing to unravel multiple
     * levels of wrapped exceptions to get the root cause.
     *
     * @param exception The exception which caused the failure.
     * @return The exception to pass to listeners.
     */
    private static AuthenticationDeniedException toDeniedException(
            final AuthenticationException exception) {
        if (exception.getCause() instanceof AuthenticationDeniedException original) {
            return original;
        }
        return new AuthenticationDeniedException(exception.getMessage(), exception);
    }
}
