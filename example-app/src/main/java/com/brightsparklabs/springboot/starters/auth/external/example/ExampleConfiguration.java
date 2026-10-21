/*
 * Maintained by brightSPARK Labs.
 * www.brightsparklabs.com
 *
 * Refer to LICENSE at repository root for license details.
 */

package com.brightsparklabs.springboot.starters.auth.external.example;

import com.brightsparklabs.springboot.starters.auth.external.AuthenticationDeniedException;
import com.brightsparklabs.springboot.starters.auth.external.AuthenticationEventListener;
import com.brightsparklabs.springboot.starters.auth.external.InternalUser;
import com.brightsparklabs.springboot.starters.auth.external.PrincipalConverter;
import java.util.Optional;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.AuthenticatedPrincipal;

/**
 * Example configuration demonstrating how a consuming application customises the starter.
 *
 * <p>It shows the two extension points consumers most commonly use:
 *
 * <ul>
 *   <li>Registering an {@link AuthenticationEventListener} bean to be notified of authentication
 *       outcomes. Listeners are additive, so any number may be registered.
 *   <li>Overriding the default {@link PrincipalConverter} bean so the application works with its
 *       own principal type ({@link MyUser}) rather than {@link InternalUser}.
 * </ul>
 *
 * @author brightSPARK Labs
 */
@Configuration
public class ExampleConfiguration {

    // -------------------------------------------------------------------------
    // CLASS VARIABLES
    // -------------------------------------------------------------------------

    /** Class logger. */
    private static final Logger logger = LoggerFactory.getLogger(ExampleConfiguration.class);

    // -------------------------------------------------------------------------
    // CONSTRUCTION
    // -------------------------------------------------------------------------

    /** Creates the configuration. Instantiated by Spring. */
    public ExampleConfiguration() {
        // Nothing to initialise.
    }

    // -------------------------------------------------------------------------
    // PUBLIC METHODS
    // -------------------------------------------------------------------------

    /**
     * Registers a listener which logs every authentication outcome.
     *
     * <p>The starter discovers this bean automatically and notifies it of each success, denial
     * (e.g. an invalid or expired token), and error (e.g. the identity provider being unreachable).
     *
     * @return The logging listener.
     */
    @Bean
    public AuthenticationEventListener eventListener() {
        return new AuthenticationEventListener() {
            @Override
            public void onAuthenticationSuccess(final InternalUser authenticatedUser) {
                logger.info("Successfully authenticated: {}", authenticatedUser);
            }

            @Override
            public void onAuthenticationDenied(
                    final AuthenticationDeniedException authDeniedException) {
                logger.warn("Authentication denied.", authDeniedException);
            }

            @Override
            public void onAuthenticationError(final AuthenticationServiceException authException) {
                logger.error("Authentication error.", authException);
            }
        };
    }

    /**
     * Replaces the starter's default principal converter so that the authenticated principal is a
     * {@link MyUser}.
     *
     * <p>The starter builds an {@link InternalUser} from the external authentication source, then
     * uses this converter to turn it into the principal stored in the security context. The reverse
     * conversion is used wherever the starter needs the {@link InternalUser} back (e.g. for
     * listener notifications and the MDC username).
     *
     * @return The converter between {@link InternalUser} and {@link MyUser}.
     */
    @Bean
    public PrincipalConverter<MyUser> principalConverter() {
        return new PrincipalConverter<MyUser>() {
            @Override
            public Class<MyUser> principalType() {
                return MyUser.class;
            }

            @Override
            public Optional<InternalUser> convertToInternalUser(MyUser principal) {
                return Optional.of(
                        new InternalUser(
                                principal.username,
                                principal.firstName,
                                principal.lastName,
                                principal.email,
                                principal.groups,
                                principal.roles,
                                principal.logoutUrl));
            }

            @Override
            public MyUser convertToPrincipal(InternalUser internalUser) {
                return new MyUser(
                        internalUser.username(),
                        internalUser.firstName(),
                        internalUser.lastName(),
                        internalUser.email(),
                        internalUser.groups(),
                        internalUser.roles(),
                        internalUser.logoutUrl());
            }
        };
    }

    // -------------------------------------------------------------------------
    // INNER CLASSES
    // -------------------------------------------------------------------------

    /**
     * An application-specific user principal.
     *
     * <p>Mirrors the fields of {@link InternalUser}, plus an application-specific field to show
     * that the principal may carry data the starter knows nothing about. That field is not part of
     * {@link InternalUser}, so it is not preserved when converting to one.
     *
     * @param username The user's unique username.
     * @param firstName The user's first name.
     * @param lastName The user's last name.
     * @param email The user's email address, if known.
     * @param groups The groups the user belongs to.
     * @param roles The roles granted to the user.
     * @param logoutUrl The URL to send the user to in order to log out, if known.
     * @param myCustomField An example application-specific field.
     */
    public record MyUser(
            String username,
            String firstName,
            String lastName,
            Optional<String> email,
            Set<String> groups,
            Set<String> roles,
            Optional<String> logoutUrl,
            String myCustomField)
            implements AuthenticatedPrincipal {

        /**
         * Creates a user with a default value for {@code myCustomField}.
         *
         * @param username The user's unique username.
         * @param firstName The user's first name.
         * @param lastName The user's last name.
         * @param email The user's email address, if known.
         * @param groups The groups the user belongs to.
         * @param roles The roles granted to the user.
         * @param logoutUrl The URL to send the user to in order to log out, if known.
         */
        public MyUser(
                String username,
                String firstName,
                String lastName,
                Optional<String> email,
                Set<String> groups,
                Set<String> roles,
                Optional<String> logoutUrl) {
            this(username, firstName, lastName, email, groups, roles, logoutUrl, "foo");
        }

        @Override
        public String getName() {
            return username;
        }
    }
}
