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
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.servlet.OAuth2ResourceServerAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

/**
 * Spring Boot autoconfiguration for the externally authenticated auth starter.
 *
 * <p>Wires the beans required to authenticate users whose principal is supplied by an external
 * source, such as OAuth2 headers.
 *
 * <p>Runs before Spring Boot's own servlet security and OAuth2 resource server auto-configurations
 * so that the filter chains defined here take precedence over Spring Boot's defaults.
 *
 * @author brightSPARK Labs
 */
@AutoConfiguration(
        before = {
            ServletWebSecurityAutoConfiguration.class,
            OAuth2ResourceServerAutoConfiguration.class
        })
@EnableConfigurationProperties(ExternallyAuthenticatedAuthStarterConfiguration.class)
public class ExternalAuthAutoConfiguration {
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

    // -------------------------------------------------------------------------
    // CLASS VARIABLES
    // -------------------------------------------------------------------------

    // -------------------------------------------------------------------------
    // INSTANCE VARIABLES
    // -------------------------------------------------------------------------

    // -------------------------------------------------------------------------
    // CONSTRUCTION
    // -------------------------------------------------------------------------

    // -------------------------------------------------------------------------
    // PUBLIC METHODS
    // -------------------------------------------------------------------------

    // Default principle converter, can be overwritten by consumers by providing a @Bean with the
    // same return type.
    @Bean
    @ConditionalOnMissingBean
    public PrincipalConverter<?> principalConverter() {
        return new IdentityPrincipalConverter();
    }

    // Converter used to create the Principal from the JWT claims.
    @Bean
    @ConditionalOnProperty(prefix = "brightsparklabs.auth", name = "method", havingValue = "jwt")
    public Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter(
            final PrincipalConverter<?> principalConverter,
            final List<AuthenticationEventListener> listeners) {
        return jwt -> {
            final InternalUser user =
                    new InternalUser(
                            jwt.getClaimAsString(CLAIM_FIELD_USERNAME),
                            jwt.getClaimAsString(CLAIM_FIELD_FIRSTNAME),
                            jwt.getClaimAsString(CLAIM_FIELD_LASTNAME),
                            jwt.getClaimAsString(CLAIM_FIELD_EMAIL),
                            ImmutableSet.copyOf(
                                    Optional.ofNullable(
                                                    jwt.getClaimAsStringList(CLAIM_FIELD_GROUPS))
                                            .orElse(ImmutableList.of())),
                            getRoles(jwt),
                            // Full name will be derived during construction.
                            "",
                            Optional.of(jwt.getIssuer() + "/protocol/openid-connect/logout"));

            listeners.forEach(listener -> listener.onAuthenticationSuccess(user));

            // Return the principal defined by the consumer and make it available to downstream
            // endpoints.
            return new PreAuthenticatedAuthenticationToken(
                    principalConverter.convertToPrincipal(user), jwt, toAuthorities(user));
        };
    }

    // Using the built in JWT support means it needs a specialised filter chain. We only apply this
    // when using JWT.
    @Bean
    @ConditionalOnProperty(prefix = "brightsparklabs.auth", name = "method", havingValue = "jwt")
    public SecurityFilterChain jwtSecurityFilterChain(
            final HttpSecurity http,
            final JwtDecoder jwtDecoder,
            final Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter,
            final PrincipalConverter<?> principalConverter,
            final ExternallyAuthenticatedAuthStarterConfiguration configuration)
            throws Exception {
        /* Deliberately not a @Bean: Spring Boot registers every Filter bean with the servlet
         * container, which would run this filter a second time outside the security chain.
         */
        final AddUserAuthToRequestFilter<?> addUserAuthToRequestFilter =
                new AddUserAuthToRequestFilter<>(
                        principalConverter,
                        configuration.mdcUsernameField(),
                        configuration.principalField());

        http
                // Don't attempt to store the user context in a session. The reverse proxy should
                // always send across the authenticated user data.
                .sessionManagement(
                        session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // Map all exceptions to a 401 response.
                .exceptionHandling(e -> e.authenticationEntryPoint(new Unauthorized401EntryPoint()))
                // Apply to all endpoints.
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                // Add the user's auth to the MDC request.
                .addFilterAfter(addUserAuthToRequestFilter, BearerTokenAuthenticationFilter.class)
                .oauth2ResourceServer(
                        oauth2 ->
                                oauth2.jwt(
                                        jwtConfigurer ->
                                                jwtConfigurer
                                                        .decoder(jwtDecoder)
                                                        .jwtAuthenticationConverter(
                                                                jwtAuthenticationConverter)));

        return http.build();
    }

    // -------------------------------------------------------------------------
    // PRIVATE METHODS
    // -------------------------------------------------------------------------

    /**
     * Extracts the roles from an {@link InternalUser} and converts them into a set of {@link
     * GrantedAuthority GrantedAuthorities}.
     *
     * @param user The user to extract the roles from.
     * @return The authorities for the user.
     */
    private ImmutableSet<GrantedAuthority> toAuthorities(final InternalUser user) {
        return user.roles().stream()
                .map(SimpleGrantedAuthority::new)
                .collect(ImmutableSet.toImmutableSet());
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
     * >
     *
     * @param jwt The claims associated with the user.
     * @return The user's groups from the {@value #CLAIM_FIELD_GROUPS} claim.
     */
    private ImmutableSet<String> getRoles(final Jwt jwt) {

        final List<String> directRoles = jwt.getClaimAsStringList(CLAIM_FIELD_ROLES);
        final Set<String> roles = Sets.newHashSet();
        Optional.ofNullable(directRoles).ifPresent(roles::addAll);

        /* Keycloak nested roles under other claims. Include them as well for backwards
         * compatibility of this library.
         */

        final Map<String, List<String>> realmRoles = jwt.getClaim(CLAIM_FIELD_REALM_ACCESS);
        Optional.ofNullable(realmRoles).map(this::getRolesFrom).ifPresent(roles::addAll);

        final Map<String, Map<String, List<String>>> clientRoles =
                jwt.getClaim(CLAIM_FIELD_RESOURCE_ACCESS);
        Optional.ofNullable(clientRoles).orElse(ImmutableMap.of()).values().stream()
                .map(this::getRolesFrom)
                .forEach(roles::addAll);

        return ImmutableSet.copyOf(roles);
    }

    /**
     * Returns the user's roles from the {@value #CLAIM_FIELD_ROLES} field.
     *
     * @param container The container which contains the roles claim.
     * @return The user's roles from the {@value #CLAIM_FIELD_ROLES} field.
     */
    private ImmutableList<String> getRolesFrom(final Map<String, List<String>> container) {
        return ImmutableList.copyOf(container.getOrDefault(CLAIM_FIELD_ROLES, ImmutableList.of()));
    }
}
