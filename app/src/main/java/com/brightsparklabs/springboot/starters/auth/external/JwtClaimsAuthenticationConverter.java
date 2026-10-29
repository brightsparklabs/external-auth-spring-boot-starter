/*
 * Maintained by brightSPARK Labs.
 * www.brightsparklabs.com
 *
 * Refer to LICENSE at repository root for license details.
 */

package com.brightsparklabs.springboot.starters.auth.external;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

/**
 * Builds the authenticated token from a validated JWT's claims, for the {@code jwt} authentication
 * method.
 *
 * <p>Claims are read using the {@code CLAIM_FIELD_*} names defined on this class. Roles are
 * gathered from the top-level, realm, and resource-access claims, and the logout URL is derived
 * from the issuer.
 *
 * @author brightSPARK Labs
 */
public class JwtClaimsAuthenticationConverter
        implements Converter<Jwt, AbstractAuthenticationToken> {

    // -------------------------------------------------------------------------
    // CONSTANTS
    // -------------------------------------------------------------------------

    /*
     * The claim names below are taken from: https://www.iana.org/assignments/jwt/jwt.xhtml#claims
     */

    /** Name of the claim containing the username of the user. */
    public static final String CLAIM_FIELD_USERNAME = "preferred_username";

    /** Name of the claim containing the firstname of the user. */
    public static final String CLAIM_FIELD_FIRSTNAME = "given_name";

    /** Name of the claim containing the lastname of the user. */
    public static final String CLAIM_FIELD_LASTNAME = "family_name";

    /** Name of the claim containing the email of the user. */
    public static final String CLAIM_FIELD_EMAIL = "email";

    /** Name of the claim containing the roles of the user. */
    public static final String CLAIM_FIELD_ROLES = "roles";

    /** Name of the claim containing the groups the user is a member of. */
    public static final String CLAIM_FIELD_GROUPS = "groups";

    /*
     * The claim names below are specific to Keycloak. Included for backwards compatibility.
     */

    /** Name of the claim containing the realm roles of the user. */
    public static final String CLAIM_FIELD_REALM_ACCESS = "realm_access";

    /** Name of the claim containing the client roles of the user. */
    public static final String CLAIM_FIELD_RESOURCE_ACCESS = "resource_access";

    /** Path appended to a Keycloak realm's issuer URL to form its logout URL. */
    private static final String KEYCLOAK_LOGOUT_PATH = "/protocol/openid-connect/logout";

    // -------------------------------------------------------------------------
    // INSTANCE VARIABLES
    // -------------------------------------------------------------------------

    /** Converter between {@link InternalUser} and the system principal. */
    private final PrincipalConverter<?> principalConverter;

    // -------------------------------------------------------------------------
    // CONSTRUCTION
    // -------------------------------------------------------------------------

    /**
     * Creates a new converter.
     *
     * @param principalConverter Converter between {@link InternalUser} and the system principal.
     */
    public JwtClaimsAuthenticationConverter(final PrincipalConverter<?> principalConverter) {
        this.principalConverter = principalConverter;
    }

    // -------------------------------------------------------------------------
    // IMPLEMENTATION: Converter
    // -------------------------------------------------------------------------

    /**
     * {@inheritDoc}
     *
     * @return An authenticated token whose principal is supplied by the {@link PrincipalConverter},
     *     with the JWT as the credentials and the user's roles as the authorities.
     */
    @Override
    public AbstractAuthenticationToken convert(final Jwt jwt) {
        final InternalUser user = toInternalUser(jwt);

        // Return the principal defined by the consumer and make it available to downstream
        // endpoints.
        return new PreAuthenticatedAuthenticationToken(
                principalConverter.convertToPrincipal(user), jwt, toAuthorities(user));
    }

    // -------------------------------------------------------------------------
    // PRIVATE METHODS
    // -------------------------------------------------------------------------

    /**
     * Builds an {@link InternalUser} from the JWT's claims.
     *
     * @param jwt The claims associated with the user.
     * @return The user described by the claims.
     */
    private static InternalUser toInternalUser(final Jwt jwt) {
        return new InternalUser(
                jwt.getClaimAsString(CLAIM_FIELD_USERNAME),
                jwt.getClaimAsString(CLAIM_FIELD_FIRSTNAME),
                jwt.getClaimAsString(CLAIM_FIELD_LASTNAME),
                Optional.ofNullable(jwt.getClaimAsString(CLAIM_FIELD_EMAIL)),
                getGroups(jwt),
                getRoles(jwt),
                getLogoutUrl(jwt));
    }

    /**
     * Extracts the roles from an {@link InternalUser} and converts them into a set of {@link
     * GrantedAuthority GrantedAuthorities}.
     *
     * @param user The user to extract the roles from.
     * @return The authorities for the user.
     */
    private static ImmutableSet<GrantedAuthority> toAuthorities(final InternalUser user) {
        return user.roles().stream()
                .map(SimpleGrantedAuthority::new)
                .collect(ImmutableSet.toImmutableSet());
    }

    /**
     * Returns the groups the user is a member of from the {@value #CLAIM_FIELD_GROUPS} claim.
     *
     * @param jwt The claims associated with the user.
     * @return The user's groups, or an empty set if the claim is absent.
     */
    private static ImmutableSet<String> getGroups(final Jwt jwt) {
        return ImmutableSet.copyOf(
                Optional.ofNullable(jwt.getClaimAsStringList(CLAIM_FIELD_GROUPS))
                        .orElse(ImmutableList.of()));
    }

    /**
     * Derives the Keycloak logout URL from the token's issuer.
     *
     * @param jwt The claims associated with the user.
     * @return The logout URL, or {@link Optional#empty()} if the token has no issuer.
     */
    private static Optional<String> getLogoutUrl(final Jwt jwt) {
        return Optional.ofNullable(jwt.getIssuer()).map(issuer -> issuer + KEYCLOAK_LOGOUT_PATH);
    }

    /**
     * Returns the user's roles from the {@value #CLAIM_FIELD_ROLES} claim from:
     *
     * <ol>
     *   <li>The supplied claims from the root.
     *   <li>Within the {@value #CLAIM_FIELD_REALM_ACCESS} claim.
     *   <li>Within the {@value #CLAIM_FIELD_RESOURCE_ACCESS} claim.
     * </ol>
     *
     * @param jwt The claims associated with the user.
     * @return The user's roles merged from all of the above claims.
     */
    private static ImmutableSet<String> getRoles(final Jwt jwt) {

        final List<String> directRoles = jwt.getClaimAsStringList(CLAIM_FIELD_ROLES);
        final Set<String> roles = Sets.newHashSet();
        Optional.ofNullable(directRoles).ifPresent(roles::addAll);

        /* Keycloak nested roles under other claims. Include them as well for backwards
         * compatibility of this library.
         */

        final Map<String, List<String>> realmRoles = jwt.getClaim(CLAIM_FIELD_REALM_ACCESS);
        Optional.ofNullable(realmRoles)
                .map(JwtClaimsAuthenticationConverter::getRolesFrom)
                .ifPresent(roles::addAll);

        final Map<String, Map<String, List<String>>> clientRoles =
                jwt.getClaim(CLAIM_FIELD_RESOURCE_ACCESS);
        Optional.ofNullable(clientRoles).orElse(ImmutableMap.of()).values().stream()
                .map(JwtClaimsAuthenticationConverter::getRolesFrom)
                .forEach(roles::addAll);

        return ImmutableSet.copyOf(roles);
    }

    /**
     * Returns the user's roles from the {@value #CLAIM_FIELD_ROLES} field.
     *
     * @param container The container which contains the roles claim.
     * @return The user's roles from the {@value #CLAIM_FIELD_ROLES} field.
     */
    private static ImmutableList<String> getRolesFrom(final Map<String, List<String>> container) {
        return ImmutableList.copyOf(container.getOrDefault(CLAIM_FIELD_ROLES, ImmutableList.of()));
    }
}
