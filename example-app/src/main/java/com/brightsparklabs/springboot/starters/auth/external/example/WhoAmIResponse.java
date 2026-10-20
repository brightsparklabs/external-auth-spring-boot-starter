/*
 * Maintained by brightSPARK Labs.
 * www.brightsparklabs.com
 *
 * Refer to LICENSE at repository root for license details.
 */

package com.brightsparklabs.springboot.starters.auth.external.example;

import com.brightsparklabs.springboot.starters.auth.external.InternalUser;
import com.brightsparklabs.springboot.starters.auth.external.example.ExampleConfiguration.MyUser;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

/**
 * Describes the authenticated user, as seen by the application.
 *
 * <p>Kept separate from {@link InternalUser} so the response shape is explicit and does not depend
 * on how {@link InternalUser} serialises.
 *
 * @param username The user's username.
 * @param fullName The user's full name.
 * @param email The user's email address.
 * @param groups The groups the user is a member of.
 * @param roles The roles assigned to the user.
 * @param authorities The authorities Spring Security granted to the request.
 * @param logoutUrl The URL to log the user out at, if known.
 * @author brightSPARK Labs
 */
public record WhoAmIResponse(
        String username,
        String fullName,
        String email,
        Set<String> groups,
        Set<String> roles,
        Set<String> authorities,
        Optional<String> logoutUrl) {

    // -------------------------------------------------------------------------
    // CONSTRUCTION
    // -------------------------------------------------------------------------

    /**
     * Creates a response describing the supplied user and authentication.
     *
     * @param user The authenticated user.
     * @param authentication The authentication for the current request.
     * @return The response.
     */
    public static WhoAmIResponse of(final InternalUser user, final Authentication authentication) {
        final Set<String> authorities = new TreeSet<>();
        authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .forEach(authorities::add);

        return new WhoAmIResponse(
                user.username(),
                user.name(),
                user.email(),
                new TreeSet<>(user.groups()),
                new TreeSet<>(user.roles()),
                authorities,
                user.logoutUrl());
    }

    /**
     * Creates a response describing the supplied user and authentication.
     *
     * @param user The authenticated user.
     * @param authentication The authentication for the current request.
     * @return The response.
     */
    public static WhoAmIResponse of(final MyUser user, final Authentication authentication) {
        final Set<String> authorities = new TreeSet<>();
        authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .forEach(authorities::add);

        return new WhoAmIResponse(
                user.username(),
                user.firstName() + " " + user.lastName() + " " + user.myCustomField(),
                user.email(),
                new TreeSet<>(user.groups()),
                new TreeSet<>(user.roles()),
                authorities,
                user.logoutUrl());
    }
}
