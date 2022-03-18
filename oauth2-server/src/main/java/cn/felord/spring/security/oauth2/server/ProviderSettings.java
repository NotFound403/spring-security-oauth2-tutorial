package cn.felord.spring.security.oauth2.server;


import org.springframework.security.oauth2.server.authorization.config.AbstractSettings;
import org.springframework.security.oauth2.server.authorization.config.ConfigurationSettingNames;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Map;

public final class ProviderSettings extends AbstractSettings {

    private ProviderSettings(Map<String, Object> settings) {
        super(settings);
    }

    /**
     * Returns the URL of the Provider's Issuer Identifier
     *
     * @return the URL of the Provider's Issuer Identifier
     */
    public String getIssuer() {
        return getSetting(ConfigurationSettingNames.Provider.ISSUER);
    }

    /**
     * Returns the Provider's OAuth 2.0 Authorization endpoint. The default is {@code /oauth2/authorize}.
     *
     * @return the Authorization endpoint
     */
    public String getAuthorizationEndpoint() {
        return getSetting(ConfigurationSettingNames.Provider.AUTHORIZATION_ENDPOINT);
    }

    /**
     * Returns the Provider's OAuth 2.0 Token endpoint. The default is {@code /oauth2/token}.
     *
     * @return the Token endpoint
     */
    public String getTokenEndpoint() {
        return getSetting(ConfigurationSettingNames.Provider.TOKEN_ENDPOINT);
    }

    /**
     * Returns the Provider's JWK Set endpoint. The default is {@code /oauth2/jwks}.
     *
     * @return the JWK Set endpoint
     */
    public String getJwkSetEndpoint() {
        return getSetting(ConfigurationSettingNames.Provider.JWK_SET_ENDPOINT);
    }

    /**
     * Returns the Provider's OAuth 2.0 Token Revocation endpoint. The default is {@code /oauth2/revoke}.
     *
     * @return the Token Revocation endpoint
     */
    public String getTokenRevocationEndpoint() {
        return getSetting(ConfigurationSettingNames.Provider.TOKEN_REVOCATION_ENDPOINT);
    }

    /**
     * Returns the Provider's OAuth 2.0 Token Introspection endpoint. The default is {@code /oauth2/introspect}.
     *
     * @return the Token Introspection endpoint
     */
    public String getTokenIntrospectionEndpoint() {
        return getSetting(ConfigurationSettingNames.Provider.TOKEN_INTROSPECTION_ENDPOINT);
    }

    /**
     * Returns the Provider's OpenID Connect 1.0 Client Registration endpoint. The default is {@code /connect/register}.
     *
     * @return the OpenID Connect 1.0 Client Registration endpoint
     */
    public String getOidcClientRegistrationEndpoint() {
        return getSetting(ConfigurationSettingNames.Provider.OIDC_CLIENT_REGISTRATION_ENDPOINT);
    }

    /**
     * Returns the Provider's OpenID Connect 1.0 UserInfo endpoint. The default is {@code /userinfo}.
     *
     * @return the OpenID Connect 1.0 UserInfo endpoint
     */
    public String getOidcUserInfoEndpoint() {
        return getSetting(ConfigurationSettingNames.Provider.OIDC_USER_INFO_ENDPOINT);
    }

    /**
     * Constructs a new {@link ProviderSettings.Builder} with the default settings.
     *
     * @return the {@link ProviderSettings.Builder}
     */
    public static ProviderSettings.Builder builder() {
        return new ProviderSettings.Builder()
                .authorizationEndpoint("/oauth2/authorize")
                .tokenEndpoint("/oauth2/token")
                .jwkSetEndpoint("/oauth2/jwks")
                .tokenRevocationEndpoint("/oauth2/revoke")
                .tokenIntrospectionEndpoint("/oauth2/introspect")
                .oidcClientRegistrationEndpoint("/connect/register")
                .oidcUserInfoEndpoint("/userinfo");
    }

    /**
     * Constructs a new {@link ProviderSettings.Builder} with the provided settings.
     *
     * @param settings the settings to initialize the builder
     * @return the {@link ProviderSettings.Builder}
     */
    public static ProviderSettings.Builder withSettings(Map<String, Object> settings) {
        Assert.notEmpty(settings, "settings cannot be empty");
        return new ProviderSettings.Builder()
                .settings(s -> s.putAll(settings));
    }

    /**
     * A builder for {@link ProviderSettings}.
     */
    public static class Builder extends AbstractBuilder<ProviderSettings, ProviderSettings.Builder> {

        private Builder() {
        }

        /**
         * Sets the URL the Provider uses as its Issuer Identifier.
         *
         * @param issuer the URL the Provider uses as its Issuer Identifier.
         * @return the {@link ProviderSettings.Builder} for further configuration
         */
        public ProviderSettings.Builder issuer(String issuer) {
            return setting(ConfigurationSettingNames.Provider.ISSUER, issuer);
        }

        /**
         * Sets the Provider's OAuth 2.0 Authorization endpoint.
         *
         * @param authorizationEndpoint the Authorization endpoint
         * @return the {@link ProviderSettings.Builder} for further configuration
         */
        public ProviderSettings.Builder authorizationEndpoint(String authorizationEndpoint) {
            Assert.hasText(authorizationEndpoint,"authorizationEndpoint is required");
            return setting(ConfigurationSettingNames.Provider.AUTHORIZATION_ENDPOINT, authorizationEndpoint);
        }

        /**
         * Sets the Provider's OAuth 2.0 Token endpoint.
         *
         * @param tokenEndpoint the Token endpoint
         * @return the {@link ProviderSettings.Builder} for further configuration
         */
        public ProviderSettings.Builder tokenEndpoint(String tokenEndpoint) {
            Assert.hasText(tokenEndpoint,"tokenEndpoint is required");
            return setting(ConfigurationSettingNames.Provider.TOKEN_ENDPOINT, tokenEndpoint);
        }

        /**
         * Sets the Provider's JWK Set endpoint.
         *
         * @param jwkSetEndpoint the JWK Set endpoint
         * @return the {@link ProviderSettings.Builder} for further configuration
         */
        public ProviderSettings.Builder jwkSetEndpoint(String jwkSetEndpoint) {
            return setting(ConfigurationSettingNames.Provider.JWK_SET_ENDPOINT, jwkSetEndpoint);
        }

        /**
         * Sets the Provider's OAuth 2.0 Token Revocation endpoint.
         *
         * @param tokenRevocationEndpoint the Token Revocation endpoint
         * @return the {@link ProviderSettings.Builder} for further configuration
         */
        public ProviderSettings.Builder tokenRevocationEndpoint(String tokenRevocationEndpoint) {
            return setting(ConfigurationSettingNames.Provider.TOKEN_REVOCATION_ENDPOINT, tokenRevocationEndpoint);
        }

        /**
         * Sets the Provider's OAuth 2.0 Token Introspection endpoint.
         *
         * @param tokenIntrospectionEndpoint the Token Introspection endpoint
         * @return the {@link ProviderSettings.Builder} for further configuration
         */
        public ProviderSettings.Builder tokenIntrospectionEndpoint(String tokenIntrospectionEndpoint) {
            return setting(ConfigurationSettingNames.Provider.TOKEN_INTROSPECTION_ENDPOINT, tokenIntrospectionEndpoint);
        }

        /**
         * Sets the Provider's OpenID Connect 1.0 Client Registration endpoint.
         *
         * @param oidcClientRegistrationEndpoint the OpenID Connect 1.0 Client Registration endpoint
         * @return the {@link ProviderSettings.Builder} for further configuration
         */
        public ProviderSettings.Builder oidcClientRegistrationEndpoint(String oidcClientRegistrationEndpoint) {
            return setting(ConfigurationSettingNames.Provider.OIDC_CLIENT_REGISTRATION_ENDPOINT, oidcClientRegistrationEndpoint);
        }

        /**
         * Sets the Provider's OpenID Connect 1.0 UserInfo endpoint.
         *
         * @param oidcUserInfoEndpoint the OpenID Connect 1.0 UserInfo endpoint
         * @return the {@link ProviderSettings.Builder} for further configuration
         */
        public ProviderSettings.Builder oidcUserInfoEndpoint(String oidcUserInfoEndpoint) {
            return setting(ConfigurationSettingNames.Provider.OIDC_USER_INFO_ENDPOINT, oidcUserInfoEndpoint);
        }

        /**
         * Builds the {@link ProviderSettings}.
         *
         * @return the {@link ProviderSettings}
         */
        @Override
        public ProviderSettings build() {
            Map<String, Object> settings = getSettings();
            validateSettings(settings);
            return new ProviderSettings(settings);
        }

        private static void validateSettings(Map<String, Object> settings) {
            String issuer = (String) settings.get(ConfigurationSettingNames.Provider.ISSUER);
            // rfc8414 https://datatracker.ietf.org/doc/html/rfc8414#section-2
            // issuer is required and no queryParams and no fragment
            Assert.hasText(issuer,"issuer is required");
            try {
                new URI(issuer).toURL();
            } catch (Exception ex) {
                throw new IllegalArgumentException("issuer must be a valid URL", ex);
            }
            UriComponents issuerUri = UriComponentsBuilder.fromUriString(issuer).build();
            if (!CollectionUtils.isEmpty(issuerUri.getQueryParams()) || issuerUri.getFragment() != null) {
                throw new IllegalArgumentException("issuer has no query or fragment components");
            }
        }
    }

}
