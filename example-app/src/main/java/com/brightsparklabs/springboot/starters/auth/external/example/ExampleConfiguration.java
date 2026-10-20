/*
 * Maintained by brightSPARK Labs.
 * www.brightsparklabs.com
 *
 * Refer to LICENSE at repository root for license details.
 */

package com.brightsparklabs.springboot.starters.auth.external.example;

import com.brightsparklabs.springboot.starters.auth.external.InternalUser;
import com.brightsparklabs.springboot.starters.auth.external.PrincipalConverter;
import java.util.Optional;
import java.util.Set;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.AuthenticatedPrincipal;

/**
 * An example configuration class for overriding the principal converter bean.
 *
 * @author brightSPARK Labs
 */
@Configuration
public class ExampleConfiguration {

    // -------------------------------------------------------------------------
    // PUBLIC METHODS
    // -------------------------------------------------------------------------

    /** Custom principal converter. */
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
                                "",
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

    public record MyUser(
            String username,
            String firstName,
            String lastName,
            String email,
            Set<String> groups,
            Set<String> roles,
            Optional<String> logoutUrl,
            String myCustomField)
            implements AuthenticatedPrincipal {

        public MyUser(
                String username,
                String firstName,
                String lastName,
                String email,
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
