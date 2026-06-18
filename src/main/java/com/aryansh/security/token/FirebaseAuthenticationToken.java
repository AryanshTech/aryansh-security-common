package com.aryansh.security.token;

import com.aryansh.security.model.AccessLevel;
import com.aryansh.security.model.AuthenticatedPrincipal;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.List;

public class FirebaseAuthenticationToken extends AbstractAuthenticationToken {

    private final AuthenticatedPrincipal principal;

    public FirebaseAuthenticationToken(AuthenticatedPrincipal principal) {
        super(buildAuthorities(principal));
        this.principal = principal;
        setAuthenticated(true);
    }

    private static List<SimpleGrantedAuthority> buildAuthorities(AuthenticatedPrincipal principal) {
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_AUTHENTICATED"));
        if (principal.accessLevel() != null) {
            authorities.add(new SimpleGrantedAuthority(principal.accessLevel().toSpringAuthority()));
        }
        if (principal.businessRole() != null) {
            authorities.add(new SimpleGrantedAuthority("ROLE_BUSINESS_" + principal.businessRole().name()));
        }
        return authorities;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public AuthenticatedPrincipal getPrincipal() {
        return principal;
    }
}
