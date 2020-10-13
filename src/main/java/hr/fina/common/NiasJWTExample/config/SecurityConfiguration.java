package com.okta.developer.jugtours.config;

import hr.fina.common.springniasauth.AbstractSAMLConfigurationBase;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SimpleSavedRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;

@EnableWebSecurity
public class SecurityConfiguration extends AbstractSAMLConfigurationBase {

    private final SAMLUserDetailsService samlUserDetailsService;
    private final JdbcTemplate jdbcTemplate;

    @Autowired
    public SecurityConfiguration(SAMLUserDetailsService samlUserDetailsService, JdbcTemplate jdbcTemplate) {
        this.samlUserDetailsService = samlUserDetailsService;
        this.jdbcTemplate = jdbcTemplate;
    }


    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
            .csrf()
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .and()
            .authorizeRequests()
                .antMatchers("/**/*.{js,html,css}").permitAll()
                .antMatchers("/", "/api/user").permitAll()
                .anyRequest().authenticated();
    }

    private KeyManager createKeyManager() throws GeneralSecurityException, IOException {

        final KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        try( InputStream stream = new FileInputStream(new File("C:\\Users\\Luka\\Downloads\\javnostdemo.jks")) ){
            keystore.load(stream, "Inicijalni1".toCharArray());
        }
        final String defaultKey = "rsvjavnost_test (fina demo ca 2014)";
        final Map<String, String> passwords = new HashMap<>();
        passwords.put(defaultKey, "Inicijalni1");

        return new JKSKeyManager(keystore, passwords, defaultKey);

    }

    @Override
    protected void configure(SAMLConfigurer samlConfigurer) throws Exception {
        final KeyManager keyManager = createKeyManager();

        samlConfigurer
                .entityBaseUrl("https://localhost:8443") //URL do aplikacije (do context-roota)
                .entityId("CN=rsvjavnost_demo, L=ZAGREB, OID.2.5.4.97=HR85821130368, O=FINA, C=HR") //Identifikator aplikacije, tipicno DN aplikativnog certifikata
                .localMetadataPath("C:\\Users\\Luka\\Documents\\Metadata.xml")  //Putanja do lokalne verzije IDP-metadata datoteke NIAS-a
                .metadataUrl("https://niastst.fina.hr/Metadata") //URL putanja do IDP-metadata datoteke NIAS-a
                .keyManager(keyManager) //KeyManager
                .userDetailsService(samlUserDetailsService) //Servis za ucitavanje autentifikacije korisnika
                .onAuthenticationFailureUrl("/errors") //Redirect u slucaju neuspjesne autentifikacije
                .onAuthenticationSuccessUrl("/") //Redirect u slucaju uspjesne autentifikacije
                .jdbcTemplate(jdbcTemplate)
                .tableName("ACTIVE_TOKEN")
                .logMessages(true);

    }

    @Bean
    @Profile("dev")
    public RequestCache refererRequestCache() {
        return new HttpSessionRequestCache() {
            @Override
            public void saveRequest(HttpServletRequest request, HttpServletResponse response) {
                String referrer = request.getHeader("referer");
                if (referrer != null) {
                    request.getSession().setAttribute("SPRING_SECURITY_SAVED_REQUEST", new SimpleSavedRequest(referrer));
                }
            }
        };
    }
}