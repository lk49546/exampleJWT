package com.okta.developer.jugtours.config;

import com.okta.developer.jugtours.config.Authentication;
import com.okta.developer.jugtours.model.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.stereotype.Service;


@Service
public class SAMLUserDetailsServiceImpl implements SAMLUserDetailsService {

    @Override
    public Object loadUserBySAML(SAMLCredential credential) throws UsernameNotFoundException {
        User user;
        final String oib = credential.getAttributeAsString("oib");
        if (oib == null) {
            final String id = credential.getAttributeAsString("http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier");
            final String firstNameForeignPerson = credential.getAttributeAsString("http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName");
            final String lastNameForeignPerson = credential.getAttributeAsString("http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName");
            user = new User(null, null, firstNameForeignPerson, lastNameForeignPerson, id);
        } else {
            final String firstName = credential.getAttributeAsString("ime");
            final String lastName = credential.getAttributeAsString("prezime");
            user = new User(null, oib, firstName, lastName, null);
        }


        return new Authentication(credential, user);
    }

}
