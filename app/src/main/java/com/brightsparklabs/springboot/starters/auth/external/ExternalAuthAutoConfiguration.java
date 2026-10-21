/*
 * Maintained by brightSPARK Labs.
 * www.brightsparklabs.com
 *
 * Refer to LICENSE at repository root for license details.
 */

package com.brightsparklabs.springboot.starters.auth.external;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.servlet.OAuth2ResourceServerAutoConfiguration;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFilter;
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
            SecurityAutoConfiguration.class,
            ServletWebSecurityAutoConfiguration.class,
            OAuth2ResourceServerAutoConfiguration.class
        })
@EnableConfigurationProperties(ExternallyAuthenticatedAuthStarterConfiguration.class)
public class ExternalAuthAutoConfiguration {
    // -------------------------------------------------------------------------
    // CONSTRUCTION
    // -------------------------------------------------------------------------

    /** Creates the auto-configuration. Instantiated by Spring Boot, not by consumers. */
    public ExternalAuthAutoConfiguration() {
        // Nothing to initialise.
    }

    // -------------------------------------------------------------------------
    // PRINCIPAL CONVERTER
    // -------------------------------------------------------------------------

    /**
     * Supplies the default principal converter, which uses {@link InternalUser} itself as the
     * system principal.
     *
     * <p>Consumers can replace it by declaring their own {@link PrincipalConverter} bean.
     *
     * @return The identity principal converter.
     */
    @Bean
    @ConditionalOnMissingBean
    public PrincipalConverter<?> principalConverter() {
        return new IdentityPrincipalConverter();
    }

    // -------------------------------------------------------------------------
    // EVENT HANDLING
    // -------------------------------------------------------------------------

    /**
     * Publishes Spring Security's authentication success and failure events, which the {@link
     * AuthenticationEventListenerDispatcher} forwards to listeners.
     *
     * <p>Failures of a type not explicitly mapped by Spring Security are published as {@link
     * AuthenticationFailureBadCredentialsEvent}s so that no failure goes unreported. Consumers can
     * replace it by declaring their own {@link AuthenticationEventPublisher} bean.
     *
     * @param publisher The application event publisher to publish the events through.
     * @return The authentication event publisher.
     */
    @Bean
    @ConditionalOnMissingBean(AuthenticationEventPublisher.class)
    public AuthenticationEventPublisher authenticationEventPublisher(
            final ApplicationEventPublisher publisher) {
        final DefaultAuthenticationEventPublisher eventPublisher =
                new DefaultAuthenticationEventPublisher(publisher);
        eventPublisher.setDefaultAuthenticationFailureEvent(
                AuthenticationFailureBadCredentialsEvent.class);
        return eventPublisher;
    }

    /**
     * Forwards authentication events to every {@link AuthenticationEventListener} bean.
     *
     * @param listeners Supplies the registered listeners. May supply none.
     * @param principalConverter Converts the authenticated principal back to an {@link
     *     InternalUser} for success notifications.
     * @return The dispatcher.
     */
    @Bean
    public AuthenticationEventListenerDispatcher authenticationEventListenerDispatcher(
            final ObjectProvider<AuthenticationEventListener> listeners,
            final PrincipalConverter<?> principalConverter) {
        return new AuthenticationEventListenerDispatcher(listeners, principalConverter);
    }

    // -------------------------------------------------------------------------
    // HEADERS
    // -------------------------------------------------------------------------

    /**
     * Collects the configured identity headers from each request for the {@code http-headers}
     * method.
     *
     * @param configuration The starter configuration, supplying the header names to collect.
     * @return The converter which collects the identity headers.
     */
    @Bean
    @ConditionalOnProperty(
            prefix = "brightsparklabs.auth",
            name = "method",
            havingValue = "http-headers")
    public AuthenticationConverter headerFieldsAuthenticationConverter(
            final ExternallyAuthenticatedAuthStarterConfiguration configuration) {
        return new HeaderFieldsAuthenticationConverter(configuration.headers());
    }

    /**
     * Authenticates the user from the collected request headers for the {@code http-headers}
     * method.
     *
     * @param principalConverter Converter between {@link InternalUser} and the system principal.
     * @param configuration The starter configuration, supplying the header names to read.
     * @return The provider which builds the user from the request headers.
     */
    @Bean
    @ConditionalOnProperty(
            prefix = "brightsparklabs.auth",
            name = "method",
            havingValue = "http-headers")
    public AuthenticationProvider headerFieldsAuthenticationProvider(
            final PrincipalConverter<?> principalConverter,
            final ExternallyAuthenticatedAuthStarterConfiguration configuration) {
        return new HeaderFieldsAuthenticationProvider(principalConverter, configuration.headers());
    }

    // -------------------------------------------------------------------------
    // DEV
    // -------------------------------------------------------------------------

    /**
     * Authenticates every request as the fixed user configured under {@code
     * brightsparklabs.auth.user}, for the {@code dev} method.
     *
     * @param principalConverter Converter between {@link InternalUser} and the system principal.
     * @param configuration The starter configuration, supplying the fixed user.
     * @return The provider which authenticates every request as the fixed user.
     */
    @Bean
    @ConditionalOnProperty(prefix = "brightsparklabs.auth", name = "method", havingValue = "dev")
    public AuthenticationProvider devAuthenticationProvider(
            final PrincipalConverter<?> principalConverter,
            final ExternallyAuthenticatedAuthStarterConfiguration configuration) {
        final InternalUser user = configuration.user();
        return new DevAuthenticationProvider(principalConverter, user);
    }

    /**
     * Supplies a placeholder authentication request for every request, for the {@code dev} method.
     *
     * <p>{@code AuthenticationFilter} skips authentication entirely when its converter returns
     * {@code null}, so without this the dev provider would never be invoked. The dev provider
     * ignores the placeholder's credentials.
     *
     * @return The converter which supplies the placeholder request.
     */
    @Bean
    @ConditionalOnProperty(prefix = "brightsparklabs.auth", name = "method", havingValue = "dev")
    public AuthenticationConverter devAuthenticationConverter() {
        return request -> new PreAuthenticatedAuthenticationToken("dev", "dev");
    }

    // -------------------------------------------------------------------------
    // JWT
    // -------------------------------------------------------------------------

    /**
     * Builds the authenticated token from a validated JWT's claims, for the {@code jwt} method.
     *
     * @param principalConverter Converter between {@link InternalUser} and the system principal.
     * @return The converter from JWT to authenticated token.
     * @see JwtClaimsAuthenticationConverter
     */
    @Bean
    @ConditionalOnProperty(prefix = "brightsparklabs.auth", name = "method", havingValue = "jwt")
    public Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter(
            final PrincipalConverter<?> principalConverter) {
        return new JwtClaimsAuthenticationConverter(principalConverter);
    }

    /**
     * Builds the filter chain for the {@code jwt} method, using Spring Security's OAuth2 resource
     * server support.
     *
     * <p>The built-in JWT support needs its own specialised chain rather than the generic {@link
     * #securityFilterChain}. The chain is stateless, requires authentication for every request, and
     * adds the authenticated user to the MDC.
     *
     * @param http The builder used to create the chain.
     * @param jwtDecoder Decodes and validates the bearer token.
     * @param jwtAuthenticationConverter Builds the authenticated token from the JWT's claims.
     * @param principalConverter Converter between {@link InternalUser} and the system principal.
     * @param configuration The starter configuration, supplying the MDC settings.
     * @return The JWT filter chain.
     * @throws Exception If the chain cannot be built.
     */
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
                /* Map authentication failures to a 401 response. Authorisation failures fall
                 * through to Spring's default access denied handler (403). Listeners are notified
                 * of authentication outcomes via the AuthenticationEventListenerDispatcher.
                 */
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
    // SECURITY FILTER CHAIN
    // -------------------------------------------------------------------------

    /**
     * Builds the generic filter chain for the {@code http-headers} and {@code dev} methods from
     * whichever converter and provider were activated above. The {@code jwt} method supplies its
     * own resource-server chain and does not use this bean.
     *
     * @param http The builder used to create the chain.
     * @param converter Extracts the authentication request from each HTTP request.
     * @param provider Authenticates the extracted request.
     * @param eventPublisher Publishes authentication events for the {@link
     *     AuthenticationEventListenerDispatcher}.
     * @param principalConverter Converter between {@link InternalUser} and the system principal.
     * @param configuration The starter configuration, supplying the MDC settings.
     * @return The generic filter chain.
     * @throws Exception If the chain cannot be built.
     */
    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain securityFilterChain(
            final HttpSecurity http,
            final AuthenticationConverter converter,
            final AuthenticationProvider provider,
            final AuthenticationEventPublisher eventPublisher,
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

        // Publish authentication events so the AuthenticationEventListenerDispatcher sees them.
        final ProviderManager authenticationManager = new ProviderManager(provider);
        authenticationManager.setAuthenticationEventPublisher(eventPublisher);

        final AuthenticationFilter authenticationFilter =
                new AuthenticationFilter(authenticationManager, converter);
        /* The default success handler redirects to the saved request (or "/"). Authentication
         * occurs on every request here, so simply continue down the filter chain instead.
         */
        authenticationFilter.setSuccessHandler((request, response, authentication) -> {});
        authenticationFilter.setFailureHandler(
                new AuthenticationEntryPointFailureHandler(new Unauthorized401EntryPoint()));

        http.securityContext(context -> context.requireExplicitSave(false))
                // Don't attempt to store the user context in a session. The reverse proxy should
                // always send across the authenticated user data.
                .sessionManagement(
                        session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                /* Create the principal BEFORE adding it to MDC. Register at AuthenticationFilter's
                 * standard position so the MDC filter below (registered relative to the same
                 * position) is guaranteed to run after it.
                 */
                .addFilterAt(authenticationFilter, AuthenticationFilter.class)
                // Add the user's auth to the MDC request.
                .addFilterAfter(addUserAuthToRequestFilter, AuthenticationFilter.class)
                /* Map authentication failures to a 401 response. Authorisation failures fall
                 * through to Spring's default access denied handler (403). Listeners are notified
                 * of authentication outcomes via the AuthenticationEventListenerDispatcher.
                 */
                .exceptionHandling(e -> e.authenticationEntryPoint(new Unauthorized401EntryPoint()))
                // Apply to all endpoints.
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
        return http.build();
    }
}
