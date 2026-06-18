package com.aryansh.security.filter;

import com.aryansh.security.context.TenantContext;
import com.aryansh.security.model.AuthenticatedPrincipal;
import com.aryansh.security.token.FirebaseAuthenticationToken;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseToken;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class FirebaseAuthenticationFilter extends OncePerRequestFilter {

    private final FirebaseAuth firebaseAuth;

    public FirebaseAuthenticationFilter(FirebaseAuth firebaseAuth) {
        this.firebaseAuth = firebaseAuth;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        try {
            String header = request.getHeader(HttpHeaders.AUTHORIZATION);
            if (header != null && header.startsWith("Bearer ")) {
                String token = header.substring(7);
                FirebaseToken decoded = firebaseAuth.verifyIdToken(token);
                AuthenticatedPrincipal principal = AuthenticatedPrincipal.fromClaims(
                        decoded.getUid(),
                        decoded.getEmail(),
                        resolveDisplayName(decoded),
                        decoded.getClaims()
                );
                SecurityContextHolder.getContext().setAuthentication(new FirebaseAuthenticationToken(principal));
                if (principal.tenantId() != null) {
                    TenantContext.setTenantId(principal.tenantId());
                }
            }
            filterChain.doFilter(request, response);
        } catch (FirebaseAuthException ex) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("""
                    {"code":"UNAUTHORIZED","message":"Invalid or expired token"}
                    """);
        } finally {
            TenantContext.clear();
        }
    }

    private String resolveDisplayName(FirebaseToken token) {
        String displayName = token.getName();
        if (displayName == null && token.getEmail() != null) {
            displayName = token.getEmail();
        }
        return displayName;
    }
}
