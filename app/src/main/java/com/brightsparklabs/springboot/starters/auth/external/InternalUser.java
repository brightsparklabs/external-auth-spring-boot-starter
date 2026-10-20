/*
 * Maintained by brightSPARK Labs.
 * www.brightsparklabs.com
 *
 * Refer to LICENSE at repository root for license details.
 */

package com.brightsparklabs.springboot.starters.auth.external;

import com.brightsparklabs.springboot.starters.auth.external.ExternallyAuthenticatedAuthStarterConfiguration.MdcPrincipalUsernameField;
import com.google.common.collect.ImmutableSet;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.Optional;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/**
 * Represents an authenticated user within the application.
 *
 * @param username The user's unique username.
 * @param firstName The user's first name.
 * @param lastName The user's last name.
 * @param email The user's email address.
 * @param groups The groups the user is a member of.
 * @param roles The roles granted to the user.
 * @param name The user's full name, derived from the firstname and lastname.
 * @param logoutUrl The URL to redirect the user to on logout, if any.
 * @author brightSPARK Labs
 */
@Validated
public record InternalUser(
        @NotBlank String username,
        @NotBlank String firstName,
        @NotBlank String lastName,
        @NotBlank String email,
        @NotNull ImmutableSet<String> groups,
        @NotNull ImmutableSet<String> roles,
        @DefaultValue("") String name,
        Optional<String> logoutUrl) {

    // -------------------------------------------------------------------------
    // CONSTRUCTION
    // -------------------------------------------------------------------------

    /** Compact constructor used to instantiate the name property. */
    public InternalUser {
        name = firstName + " " + lastName;
    }

    // -------------------------------------------------------------------------
    // PUBLIC METHODS
    // -------------------------------------------------------------------------

    /**
     * Extracts the relevant value to use as the user's username from the supplied {@link
     * MdcPrincipalUsernameField}.
     *
     * @param usernameField The field to extract the value from.
     * @return The value of the requested field.
     */
    public String getPrincipalUsername(final MdcPrincipalUsernameField usernameField) {
        return switch (usernameField) {
            case EMAIL -> this.email;
            case USERNAME -> this.username;
            case FIRST_NAME -> this.firstName;
            case LAST_NAME -> this.lastName;
            case FULL_NAME -> this.name;
        };
    }
}
