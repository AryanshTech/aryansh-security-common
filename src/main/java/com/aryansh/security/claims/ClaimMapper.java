package com.aryansh.security.claims;

import com.aryansh.security.model.AccessLevel;
import com.aryansh.security.model.AuthenticatedPrincipal;
import com.aryansh.security.model.BusinessRole;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class ClaimMapper {

    private ClaimMapper() {
    }

    public static AuthenticatedPrincipal fromTokenClaims(
            String uid,
            String email,
            String displayName,
            Map<String, Object> claims
    ) {
        AccessLevel accessLevel = resolveAccessLevel(claims);
        BusinessRole businessRole = resolveBusinessRole(claims, accessLevel);
        String tenantId = claims.get("tenantId") instanceof String tid ? tid : null;
        List<String> services = resolveServices(claims, accessLevel);
        return new AuthenticatedPrincipal(uid, email, displayName, accessLevel, businessRole, tenantId, services);
    }

    public static Map<String, Object> toClaims(
            AccessLevel accessLevel,
            String tenantId,
            BusinessRole businessRole,
            List<String> services
    ) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("accessLevel", accessLevel.toClaimValue());
        if (tenantId != null) {
            claims.put("tenantId", tenantId);
        }
        if (businessRole != null) {
            claims.put("businessRole", businessRole.toClaimValue());
        }
        if (services != null && !services.isEmpty()) {
            claims.put("services", services);
        }
        return claims;
    }

    private static AccessLevel resolveAccessLevel(Map<String, Object> claims) {
        if (claims.get("accessLevel") instanceof String level) {
            return AccessLevel.fromClaim(level);
        }
        if (claims.get("role") instanceof String legacyRole) {
            return AccessLevel.fromClaim(legacyRole);
        }
        return null;
    }

    private static BusinessRole resolveBusinessRole(Map<String, Object> claims, AccessLevel accessLevel) {
        if (claims.get("businessRole") instanceof String role) {
            return BusinessRole.fromClaim(role);
        }
        if (accessLevel == AccessLevel.BUSINESS_MEMBER && claims.get("role") instanceof String legacyRole) {
            return BusinessRole.fromClaim(legacyRole);
        }
        if (accessLevel == AccessLevel.BUSINESS_OWNER) {
            return BusinessRole.ADMIN;
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private static List<String> resolveServices(Map<String, Object> claims, AccessLevel accessLevel) {
        if (claims.get("services") instanceof List<?> list) {
            List<String> services = new ArrayList<>();
            for (Object item : list) {
                if (item instanceof String service) {
                    services.add(service);
                }
            }
            if (!services.isEmpty()) {
                return services;
            }
        }
        if (accessLevel == null) {
            return List.of();
        }
        return switch (accessLevel) {
            case PLATFORM_ADMIN -> List.of("auth", "business-manager", "marketing-hub");
            case PLATFORM_TEAM -> List.of("business-manager", "marketing-hub");
            case BUSINESS_OWNER, BUSINESS_MEMBER -> List.of("business-manager");
        };
    }

    public static AccessLevel memberRoleToAccessLevel(String legacyRole) {
        String normalized = legacyRole.trim().toLowerCase(Locale.ROOT);
        return switch (normalized) {
            case "tenant_owner" -> AccessLevel.BUSINESS_OWNER;
            case "tenant_admin", "tenant_editor", "tenant_viewer" -> AccessLevel.BUSINESS_MEMBER;
            default -> AccessLevel.fromClaim(normalized);
        };
    }

    public static BusinessRole legacyRoleToBusinessRole(String legacyRole) {
        return BusinessRole.fromClaim(legacyRole);
    }
}
