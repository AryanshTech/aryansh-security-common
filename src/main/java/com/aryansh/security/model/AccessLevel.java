package com.aryansh.security.model;

import java.util.Locale;

public enum AccessLevel {
    PLATFORM_ADMIN,
    PLATFORM_TEAM,
    BUSINESS_OWNER,
    BUSINESS_MEMBER;

    public String toClaimValue() {
        return name().toLowerCase(Locale.ROOT);
    }

    public String toSpringAuthority() {
        return "ROLE_" + name();
    }

    public static AccessLevel fromClaim(String claim) {
        if (claim == null || claim.isBlank()) {
            throw new IllegalArgumentException("accessLevel claim is missing");
        }
        String normalized = claim.trim().toLowerCase(Locale.ROOT);
        return switch (normalized) {
            case "platform_admin", "platform_super_admin" -> PLATFORM_ADMIN;
            case "platform_team" -> PLATFORM_TEAM;
            case "business_owner", "tenant_owner" -> BUSINESS_OWNER;
            case "business_member", "tenant_admin", "tenant_editor", "tenant_viewer" -> BUSINESS_MEMBER;
            default -> AccessLevel.valueOf(claim.trim().toUpperCase(Locale.ROOT));
        };
    }

    public boolean isPlatformUser() {
        return this == PLATFORM_ADMIN || this == PLATFORM_TEAM;
    }
}
