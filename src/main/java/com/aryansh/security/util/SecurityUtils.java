package com.aryansh.security.util;

import com.aryansh.security.model.AuthenticatedPrincipal;
import com.aryansh.security.token.FirebaseAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public final class SecurityUtils {

    private SecurityUtils() {
    }

    public static AuthenticatedPrincipal currentPrincipal() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof FirebaseAuthenticationToken token) {
            return token.getPrincipal();
        }
        throw new IllegalStateException("Authenticated principal not available");
    }

    public static String currentUid() {
        return currentPrincipal().uid();
    }
}
