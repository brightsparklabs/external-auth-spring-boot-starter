/*
 * Maintained by brightSPARK Labs.
 * www.brightsparklabs.com
 *
 * Refer to LICENSE at repository root for license details.
 */

package com.brightsparklabs.springboot.starters.auth.external;

import com.brightsparklabs.springboot.starters.auth.external.ExternallyAuthenticatedAuthStarterConfiguration.ValidExternalAuthDevConfiguration;
import com.google.common.collect.ImmutableSet;
import jakarta.validation.Constraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import jakarta.validation.Payload;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.Optional;
import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/**
 * Binds the {@code brightsparklabs.auth} configuration tree used by the externally authenticated
 * auth starter.
 *
 * <p>The active authentication method is selected via {@link #method()}.
 *
 * @param method The authentication method to use.
 * @param mdcUsernameField Key in the MDC that the authenticated user's username is stored against,
 *     used for access logging. Shared by all methods.
 * @param principalField The property on the user principal that should act as the user's username.
 *     If left {@code null} then the {@link MdcPrincipalUsernameField#USERNAME} field is used.
 * @param user The user to use for the {@link AuthMethod#DEV} method. Ignored otherwise.
 * @param headers The header fields to read the user from for the {@link AuthMethod#HTTP_HEADERS}
 *     method. Defaults to {@link HttpHeadersConfiguration#DEFAULT_INSTANCE} when that method is in
 *     use and no value is supplied. Ignored otherwise.
 * @author brightSPARK Labs
 */
@Validated
@ValidExternalAuthDevConfiguration
@ConfigurationProperties(prefix = "brightsparklabs.auth")
public record ExternallyAuthenticatedAuthStarterConfiguration(
        @NotNull AuthMethod method,
        @DefaultValue("req.username") String mdcUsernameField,
        MdcPrincipalUsernameField principalField,
        Optional<InternalUser> user,
        Optional<HttpHeadersConfiguration> headers) {

    // -------------------------------------------------------------------------
    // CONSTRUCTION
    // -------------------------------------------------------------------------

    /**
     * Creates a new configuration, applying the default header fields when the {@link
     * AuthMethod#HTTP_HEADERS} method is in use and no header configuration is supplied.
     */
    public ExternallyAuthenticatedAuthStarterConfiguration {

        // Provide a default header config value if nothing is provided.
        if (method == AuthMethod.HTTP_HEADERS && headers.isEmpty()) {
            headers = Optional.of(HttpHeadersConfiguration.DEFAULT_INSTANCE);
        }

        if (principalField == null) {
            principalField = MdcPrincipalUsernameField.USERNAME;
        }
    }

    // -------------------------------------------------------------------------
    // INNER CLASSES
    // -------------------------------------------------------------------------

    /**
     * Configures which request headers the {@link AuthMethod#HTTP_HEADERS} method reads the user's
     * details from.
     *
     * <p>Each component lists the candidate header names to attempt, in priority order. Any
     * component that is {@code null} or empty falls back to its default set of headers.
     *
     * @param usernameHeaderFields The headers to read the username from.
     * @param firstNameHeaderFields The headers to read the first name from.
     * @param lastNameHeaderFields The headers to read the last name from.
     * @param emailHeaderFields The headers to read the email address from.
     * @param groupsHeaderFields The headers to read the groups the user is a member of from.
     * @param rolesHeaderFields The headers to read the user's roles from.
     */
    public record HttpHeadersConfiguration(
            Set<String> usernameHeaderFields,
            Set<String> firstNameHeaderFields,
            Set<String> lastNameHeaderFields,
            Set<String> emailHeaderFields,
            Set<String> groupsHeaderFields,
            Set<String> rolesHeaderFields) {

        /** The default header fields to attempt to retrieve the username from in order. */
        private static final Set<String> DEFAULT_USERNAME_HEADER_FIELDS =
                ImmutableSet.of(
                        "X-Auth-Request-Preferred-Username",
                        "X-Forwarded-Preferred-Username",
                        "X-Auth-Username");

        /** The default header fields to attempt to retrieve the first name from in order. */
        private static final Set<String> DEFAULT_FIRST_NAME_HEADER_FIELDS =
                ImmutableSet.of(
                        "X-Auth-Request-Given-Name", "X-Forwarded-Given-Name", "X-Auth-Given-Name");

        /** The default header fields to attempt to retrieve the last name from in order. */
        private static final Set<String> DEFAULT_LAST_NAME_HEADER_FIELDS =
                ImmutableSet.of(
                        "X-Auth-Request-Family-Name",
                        "X-Forwarded-Family-Name",
                        "X-Auth-Family-Name");

        /** The default header fields to attempt to retrieve the email from in order. */
        private static final Set<String> DEFAULT_EMAIL_HEADER_FIELDS =
                ImmutableSet.of("X-Auth-Request-Email", "X-Forwarded-Email", "X-Auth-Email");

        /** The default header fields to attempt to retrieve the groups from in order. */
        private static final Set<String> DEFAULT_GROUPS_HEADER_FIELDS =
                ImmutableSet.of("X-Auth-Request-Groups", "X-Forwarded-Groups", "X-Auth-Groups");

        /** The default header fields to attempt to retrieve the roles from in order. */
        private static final Set<String> DEFAULT_ROLES_HEADER_FIELDS =
                ImmutableSet.of("X-Auth-Request-Roles", "X-Forwarded-Roles", "X-Auth-Roles");

        /** Default instance of this record. */
        public static HttpHeadersConfiguration DEFAULT_INSTANCE =
                new HttpHeadersConfiguration(
                        DEFAULT_USERNAME_HEADER_FIELDS,
                        DEFAULT_FIRST_NAME_HEADER_FIELDS,
                        DEFAULT_LAST_NAME_HEADER_FIELDS,
                        DEFAULT_EMAIL_HEADER_FIELDS,
                        DEFAULT_GROUPS_HEADER_FIELDS,
                        DEFAULT_ROLES_HEADER_FIELDS);

        /**
         * Creates a new header configuration, replacing any {@code null} or empty component with
         * its default set of headers.
         */
        public HttpHeadersConfiguration {

            // When populated via the Spring Boot configuration, unsupplied values may be null. If
            // so, replace them with the default value.
            if (usernameHeaderFields == null || usernameHeaderFields.isEmpty()) {
                usernameHeaderFields = DEFAULT_USERNAME_HEADER_FIELDS;
            }

            if (firstNameHeaderFields == null || firstNameHeaderFields.isEmpty()) {
                firstNameHeaderFields = DEFAULT_FIRST_NAME_HEADER_FIELDS;
            }

            if (lastNameHeaderFields == null || lastNameHeaderFields.isEmpty()) {
                lastNameHeaderFields = DEFAULT_LAST_NAME_HEADER_FIELDS;
            }

            if (emailHeaderFields == null || emailHeaderFields.isEmpty()) {
                emailHeaderFields = DEFAULT_EMAIL_HEADER_FIELDS;
            }

            if (groupsHeaderFields == null || groupsHeaderFields.isEmpty()) {
                groupsHeaderFields = DEFAULT_GROUPS_HEADER_FIELDS;
            }

            if (rolesHeaderFields == null || rolesHeaderFields.isEmpty()) {
                rolesHeaderFields = DEFAULT_ROLES_HEADER_FIELDS;
            }
        }
    }

    /** Validates that a {@link AuthMethod#DEV} configuration contains a dummy user. */
    @Target({ElementType.TYPE})
    @Retention(RetentionPolicy.RUNTIME)
    @Documented
    @Constraint(validatedBy = ExternalAuthDevConfigurationValidator.class)
    public @interface ValidExternalAuthDevConfiguration {
        /**
         * Returns the message shown when validation fails.
         *
         * @return The validation failure message.
         */
        String message() default "A dummy user must be defined when using the developer method.";

        /**
         * Returns the validation groups this constraint belongs to.
         *
         * @return The validation groups.
         */
        Class<?>[] groups() default {};

        /**
         * Returns the payload associated with this constraint.
         *
         * @return The constraint payload.
         */
        Class<? extends Payload>[] payload() default {};
    }

    /** Enforces the {@link ValidExternalAuthDevConfiguration} cross-field constraint. */
    public static class ExternalAuthDevConfigurationValidator
            implements ConstraintValidator<
                    ValidExternalAuthDevConfiguration,
                    ExternallyAuthenticatedAuthStarterConfiguration> {

        /**
         * Checks that a dummy user is present whenever the {@link AuthMethod#DEV} method is in use.
         *
         * <p>A {@code null} configuration is treated as valid so that null handling is left to the
         * {@link NotNull} and {@link NotBlank} constraints.
         *
         * @param value The configuration to validate.
         * @param context The context in which the constraint is evaluated.
         * @return {@code true} if the configuration is internally consistent, {@code false}
         *     otherwise.
         */
        @Override
        public boolean isValid(
                final ExternallyAuthenticatedAuthStarterConfiguration value,
                final ConstraintValidatorContext context) {
            // If the value is null, let @NotBlank or @NotNull handle it.
            if (value == null) {
                return true;
            }

            // If the method is DEV then a user must be provided.
            return value.method() != AuthMethod.DEV || value.user().isPresent();
        }
    }

    /** The supported authentication methods. */
    public enum AuthMethod {
        /**
         * User principal properties are read from the claims of a JWT bearer token.
         *
         * <p>The token is validated by Spring Boot's OAuth2 resource server support, so either
         * {@code spring.security.oauth2.resourceserver.jwt.issuer-uri} or {@code
         * spring.security.oauth2.resourceserver.jwt.public-key-location} must also be set.
         */
        JWT,

        /** User principal properties are provided via OAuth2 headers. */
        HTTP_HEADERS,

        /**
         * A fixed user principal is provided for all requests.
         *
         * <p>DO NOT USE THIS IN PRODUCTION.
         */
        DEV,
    }

    /**
     * The fields in the {@link InternalUser} that can be inserted into the MDC username request
     * field.
     */
    public enum MdcPrincipalUsernameField {
        /** Corresponds to {@link InternalUser#username()}. */
        USERNAME,

        /** Corresponds to {@link InternalUser#firstName()}. */
        FIRST_NAME,

        /** Corresponds to {@link InternalUser#lastName()}. */
        LAST_NAME,

        /** Corresponds to {@link InternalUser#fullName()}. */
        FULL_NAME,

        /** Corresponds to {@link InternalUser#email()}. */
        EMAIL
    }
}
