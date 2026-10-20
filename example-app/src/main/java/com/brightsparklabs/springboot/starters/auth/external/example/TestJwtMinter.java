/*
 * Maintained by brightSPARK Labs.
 * www.brightsparklabs.com
 *
 * Refer to LICENSE at repository root for license details.
 */

package com.brightsparklabs.springboot.starters.auth.external.example;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Command line tool which mints a JWT for the {@code jwt-local} profile.
 *
 * <p>The token is signed with the test-only private key in {@code example-app/keys/} and printed to
 * standard output. Run it via {@code ./gradlew -q :example-app:mintJwt --args='...'}.
 *
 * <p>Supported arguments (all optional, in {@code --name=value} form):
 *
 * <ul>
 *   <li>{@code --username} The {@code preferred_username} claim. Defaults to {@code alice}.
 *   <li>{@code --first-name} The {@code given_name} claim. Defaults to the capitalised username.
 *   <li>{@code --last-name} The {@code family_name} claim. Defaults to {@code Example}.
 *   <li>{@code --email} The {@code email} claim. Defaults to {@code <username>@example.com}.
 *   <li>{@code --roles} Comma-separated {@code roles} claim. Defaults to none.
 *   <li>{@code --groups} Comma-separated {@code groups} claim. Defaults to none.
 *   <li>{@code --expires-in-seconds} Lifetime of the token; negative values mint an expired token.
 *       Defaults to {@code 3600}.
 *   <li>{@code --private-key} Path to the PKCS#8 PEM private key. Defaults to {@code
 *       keys/test-private.pem}.
 * </ul>
 *
 * @author brightSPARK Labs
 */
public final class TestJwtMinter {

    // -------------------------------------------------------------------------
    // CONSTANTS
    // -------------------------------------------------------------------------

    /**
     * Issuer placed in minted tokens. Must be a URL as the starter derives a logout URL from it.
     */
    public static final String ISSUER = "http://localhost:8080/example-local";

    /** Default path to the test-only private key, relative to the example-app directory. */
    public static final String DEFAULT_PRIVATE_KEY_PATH = "keys/test-private.pem";

    /** Default token lifetime in seconds. */
    public static final long DEFAULT_EXPIRES_IN_SECONDS = 3600;

    // -------------------------------------------------------------------------
    // CONSTRUCTION
    // -------------------------------------------------------------------------

    /** Not instantiable. */
    private TestJwtMinter() {}

    // -------------------------------------------------------------------------
    // PUBLIC METHODS
    // -------------------------------------------------------------------------

    /**
     * Entry point.
     *
     * @param args The command line arguments, in {@code --name=value} form.
     * @throws IOException If the private key cannot be read.
     * @throws GeneralSecurityException If the private key cannot be parsed.
     * @throws JOSEException If the token cannot be signed.
     */
    public static void main(final String[] args)
            throws IOException, GeneralSecurityException, JOSEException {
        final Map<String, String> options = parseArguments(args);
        final String username = options.getOrDefault("username", "alice");
        final long expiresInSeconds =
                Long.parseLong(
                        options.getOrDefault(
                                "expires-in-seconds", String.valueOf(DEFAULT_EXPIRES_IN_SECONDS)));
        final Instant now = Instant.now();

        final JWTClaimsSet claims =
                new JWTClaimsSet.Builder()
                        .issuer(ISSUER)
                        .subject(username)
                        .jwtID(UUID.randomUUID().toString())
                        .issueTime(Date.from(now))
                        .expirationTime(Date.from(now.plusSeconds(expiresInSeconds)))
                        .claim("preferred_username", username)
                        .claim(
                                "given_name",
                                options.getOrDefault("first-name", capitalise(username)))
                        .claim("family_name", options.getOrDefault("last-name", "Example"))
                        .claim("email", options.getOrDefault("email", username + "@example.com"))
                        .claim("roles", toList(options.get("roles")))
                        .claim("groups", toList(options.get("groups")))
                        .build();

        final RSAPrivateKey privateKey =
                readPrivateKey(
                        Path.of(options.getOrDefault("private-key", DEFAULT_PRIVATE_KEY_PATH)));
        final SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims);
        jwt.sign(new RSASSASigner(privateKey));

        System.out.println(jwt.serialize());
    }

    // -------------------------------------------------------------------------
    // PRIVATE METHODS
    // -------------------------------------------------------------------------

    /**
     * Parses {@code --name=value} arguments into a map.
     *
     * @param args The command line arguments.
     * @return The parsed options, keyed by name.
     * @throws IllegalArgumentException If an argument is not in {@code --name=value} form.
     */
    private static Map<String, String> parseArguments(final String[] args) {
        final Map<String, String> options = new HashMap<>();
        for (final String arg : args) {
            final int separator = arg.indexOf('=');
            if (!arg.startsWith("--") || separator < 0) {
                throw new IllegalArgumentException(
                        "Arguments must be in --name=value form, but got: " + arg);
            }
            options.put(arg.substring(2, separator), arg.substring(separator + 1));
        }
        return options;
    }

    /**
     * Upper-cases the first character of a value.
     *
     * @param value The value to capitalise.
     * @return The capitalised value, or the value unchanged if it is empty.
     */
    private static String capitalise(final String value) {
        if (value.isEmpty()) {
            return value;
        }
        return Character.toUpperCase(value.charAt(0)) + value.substring(1);
    }

    /**
     * Splits a comma-separated value into a list, ignoring blank entries.
     *
     * @param value The comma-separated value, or {@code null}.
     * @return The entries, or an empty list if the value is {@code null} or blank.
     */
    private static List<String> toList(final String value) {
        if (value == null || value.isBlank()) {
            return List.of();
        }
        return Arrays.stream(value.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList();
    }

    /**
     * Reads an RSA private key from a PKCS#8 PEM file.
     *
     * @param path The path to the PEM file.
     * @return The private key.
     * @throws IOException If the file cannot be read.
     * @throws GeneralSecurityException If the key cannot be parsed.
     */
    private static RSAPrivateKey readPrivateKey(final Path path)
            throws IOException, GeneralSecurityException {
        final String base64 =
                Files.readString(path)
                        .replace("-----BEGIN PRIVATE KEY-----", "")
                        .replace("-----END PRIVATE KEY-----", "")
                        .replaceAll("\\s", "");
        final PKCS8EncodedKeySpec keySpec =
                new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64));
        return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    }
}
