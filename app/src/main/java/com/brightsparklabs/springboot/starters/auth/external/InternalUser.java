/*
 * Maintained by brightSPARK Labs.
 * www.brightsparklabs.com
 *
 * Refer to LICENSE at repository root for license details.
 */

package com.brightsparklabs.springboot.starters.auth.external;

import com.brightsparklabs.springboot.starters.auth.external.ExternallyAuthenticatedAuthStarterConfiguration.MdcPrincipalUsernameField;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.Optional;
import java.util.Set;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.validation.annotation.Validated;

/**
 * Represents an authenticated user within the application.
 *
 * <p>Implements {@link AuthenticatedPrincipal} so that {@code Authentication#getName()} resolves to
 * the user's {@link #username()} when this record is used as a principal.
 *
 * @param username The user's unique username.
 * @param firstName The user's first name.
 * @param lastName The user's last name.
 * @param email The user's email address.
 * @param groups The groups the user is a member of.
 * @param roles The roles granted to the user.
 * @param logoutUrl The URL to redirect the user to on logout, if any.
 * @author brightSPARK Labs
 */
@Validated
public record InternalUser(
        @NotBlank String username,
        @NotBlank String firstName,
        @NotBlank String lastName,
        Optional<String> email,
        @NotNull Set<String> groups,
        @NotNull Set<String> roles,
        Optional<String> logoutUrl)
        implements AuthenticatedPrincipal {

    // -------------------------------------------------------------------------
    // CONSTRUCTION
    // -------------------------------------------------------------------------

    /** Compact constructor used to ensure null values are properly instantiated as optionals. */
    public InternalUser {

        // Do some null checking as Spring Boot doesn't automatically convert missing values to
        // Optionals.
        if (email == null) {
            email = Optional.empty();
        }

        if (logoutUrl == null) {
            logoutUrl = Optional.empty();
        }
    }

    // -------------------------------------------------------------------------
    // IMPLEMENTATION: AuthenticatedPrincipal
    // -------------------------------------------------------------------------

    @Override
    public String getName() {
        return username;
    }

    // -------------------------------------------------------------------------
    // PUBLIC METHODS
    // -------------------------------------------------------------------------

    /** {@return the user's full name, derived from the first name and last name} */
    public String getFullName() {
        return firstName + " " + lastName;
    }

    /**
     * Extracts the relevant value to use as the user's username from the supplied {@link
     * MdcPrincipalUsernameField}.
     *
     * @param usernameField The field to extract the value from.
     * @return The value of the requested field.
     */
    public Optional<String> getPrincipalUsername(final MdcPrincipalUsernameField usernameField) {
        return switch (usernameField) {
            case EMAIL -> this.email;
            case USERNAME -> Optional.of(this.username);
            case FIRST_NAME -> Optional.of(this.firstName);
            case LAST_NAME -> Optional.of(this.lastName);
            case FULL_NAME -> Optional.of(this.getFullName());
        };
    }
}
