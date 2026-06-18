package com.aryansh.security.model;

import java.util.Locale;

public enum BusinessRole {
    ADMIN,
    EDITOR,
    VIEWER;

    public String toClaimValue() {
        return name().toLowerCase(Locale.ROOT);
    }

    public static BusinessRole fromClaim(String claim) {
        if (claim == null || claim.isBlank()) {
            return null;
        }
        String normalized = claim.trim().toLowerCase(Locale.ROOT);
        return switch (normalized) {
            case "admin", "tenant_admin" -> ADMIN;
            case "editor", "tenant_editor" -> EDITOR;
            case "viewer", "tenant_viewer" -> VIEWER;
            default -> BusinessRole.valueOf(claim.trim().toUpperCase(Locale.ROOT));
        };
    }
}
