package com.aryansh.security.model;

import com.aryansh.security.claims.ClaimMapper;

import java.util.List;
import java.util.Map;

public record AuthenticatedPrincipal(
        String uid,
        String email,
        String displayName,
        AccessLevel accessLevel,
        BusinessRole businessRole,
        String tenantId,
        List<String> services
) {
    public boolean isPlatformAdmin() {
        return accessLevel == AccessLevel.PLATFORM_ADMIN;
    }

    public boolean isPlatformUser() {
        return accessLevel != null && accessLevel.isPlatformUser();
    }

    public boolean hasService(String serviceId) {
        return services != null && services.contains(serviceId);
    }

    public static AuthenticatedPrincipal fromClaims(
            String uid,
            String email,
            String displayName,
            Map<String, Object> claims
    ) {
        return ClaimMapper.fromTokenClaims(uid, email, displayName, claims);
    }
}
