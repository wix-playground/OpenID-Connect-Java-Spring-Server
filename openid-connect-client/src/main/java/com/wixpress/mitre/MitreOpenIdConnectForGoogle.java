package com.wixpress.mitre;

import org.mitre.jose.keystore.JWKSetKeyStore;
import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.jwt.signer.service.impl.DefaultJWTSigningAndValidationService;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.RegisteredClient;
import org.mitre.openid.connect.client.service.impl.StaticClientConfigurationService;
import org.mitre.openid.connect.client.service.impl.StaticServerConfigurationService;
import org.mitre.openid.connect.client.service.impl.StaticSingleIssuerService;
import org.mitre.openid.connect.config.ServerConfiguration;
import org.springframework.context.annotation.Bean;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

/**
 * Created by Jefim_Matzkin on 2/10/15.
 */
public class MitreOpenIdConnectForGoogle {
    private static final String ACCOUNTS_GOOGLE_COM = "accounts.google.com";

    protected String googleClientId,
            googleClientName,
            googleClientSecret;

    @Bean(name = {"staticIssuerService"})
    public StaticSingleIssuerService createStaticSingleIssuerService() {
        StaticSingleIssuerService ret = new StaticSingleIssuerService();
        ret.setIssuer(ACCOUNTS_GOOGLE_COM);
        return ret;
    }

    @Bean(name = {"staticServerConfigurationService"})
    public StaticServerConfigurationService createStaticServerConfigurationService() {
        StaticServerConfigurationService ret = new StaticServerConfigurationService();
        Map<String, ServerConfiguration> servers = new HashMap<>();
        servers.put(ACCOUNTS_GOOGLE_COM, createServerConfiguration());
        ret.setServers(servers);
        return ret;
    }

    private ServerConfiguration createServerConfiguration() {
        ServerConfiguration cfg = new ServerConfiguration();
        cfg.setIssuer(ACCOUNTS_GOOGLE_COM);
        cfg.setAuthorizationEndpointUri("https://accounts.google.com/o/oauth2/auth");
        cfg.setTokenEndpointUri("https://accounts.google.com/o/oauth2/token");
        cfg.setUserInfoUri("https://www.googleapis.com/plus/v1/people/me/openIdConnect");
        // cfg.setUserInfoUri("https://www.googleapis.com/oauth2/v2/userinfo");
        cfg.setJwksUri("https://www.googleapis.com/oauth2/v2/certs");
        cfg.setNonceEnabled(false);
        return cfg;
    }

    @Bean(name = {"staticClientConfigurationService"})
    public StaticClientConfigurationService createStaticClientConfigurationService() {
        StaticClientConfigurationService ret = new StaticClientConfigurationService();
        Map<String, RegisteredClient> clients = new HashMap<>();
        RegisteredClient googleClientConfig = createGoogleClientConfig();
        clients.put(ACCOUNTS_GOOGLE_COM, googleClientConfig);
        ret.setClients(clients);
        return ret;
    }

    @Bean
    public JWTSigningAndValidationService createJWKSetCacheService() throws InvalidKeySpecException, NoSuchAlgorithmException {
        JWKSetKeyStore store = new JWKSetKeyStore();
        DefaultJWTSigningAndValidationService ret = new DefaultJWTSigningAndValidationService(store);
        ret.setDefaultSignerKeyId("rsa1");
        ret.setDefaultSigningAlgorithmName("RS256");
        return ret;
    }

    private RegisteredClient createGoogleClientConfig() {
        RegisteredClient client = new RegisteredClient();
        client.setTokenEndpointAuthMethod(ClientDetailsEntity.AuthMethod.SECRET_POST);
        client.setScope(new HashSet<>(Arrays.asList("openid", "email", "profile")));
        client.setClientId(googleClientId);
        client.setClientSecret(googleClientSecret);
        client.setClientName(googleClientName);
        return client;
    }

    public void setGoogleClientId(String googleClientId) {
        this.googleClientId = googleClientId;
    }

    public void setGoogleClientName(String googleClientName) {
        this.googleClientName = googleClientName;
    }

    public void setGoogleClientSecret(String googleClientSecret) {
        this.googleClientSecret = googleClientSecret;
    }
}
