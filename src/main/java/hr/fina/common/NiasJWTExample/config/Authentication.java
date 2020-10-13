package com.okta.developer.jugtours.config;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashSet;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.okta.developer.jugtours.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.saml.SAMLCredential;

import hr.fina.common.springniasauth.SAMLPrincipal;

public class Authentication implements UserDetails,SAMLPrincipal,Serializable {

    /**
     *
     */
    private static final long serialVersionUID = 1L;
    private SAMLCredential samlCredential;
    private User user;

    public Authentication(SAMLCredential samlCredential,User user) {
        this.user = user;
        this.samlCredential = samlCredential;
    }


    @Override
    public SAMLCredential getSamlCredential() {
        return samlCredential;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Stream.of(new SimpleGrantedAuthority("USER")).collect(Collectors.toSet());
    }

    @Override
    public String getPassword() {
        return "N/A";
    }

    @Override
    public String getUsername() {
        return samlCredential.getNameID().getValue();
    }

    @Override
    public boolean isAccountNonExpired() {
        return false;
    }

    @Override
    public boolean isAccountNonLocked() {
        return false;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

}
