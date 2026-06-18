package com.aryansh.security.access;

import com.aryansh.security.exception.ForbiddenException;
import com.aryansh.security.model.AccessLevel;
import com.aryansh.security.model.AuthenticatedPrincipal;
import com.aryansh.security.model.BusinessRole;
import java.util.EnumSet;
import java.util.Set;

public class AccessEvaluator {

    private static final Set<AccessLevel> PLATFORM_LEVELS = EnumSet.of(
            AccessLevel.PLATFORM_ADMIN,
            AccessLevel.PLATFORM_TEAM
    );

    private static final Set<BusinessRole> VIEW_ROLES = EnumSet.of(
            BusinessRole.ADMIN,
            BusinessRole.EDITOR,
            BusinessRole.VIEWER
    );

    private static final Set<BusinessRole> EDIT_ROLES = EnumSet.of(
            BusinessRole.ADMIN,
            BusinessRole.EDITOR
    );

    private static final Set<BusinessRole> ADMIN_ROLES = EnumSet.of(BusinessRole.ADMIN);

    public void requireAccessLevel(AuthenticatedPrincipal principal, AccessLevel... levels) {
        if (principal.accessLevel() == null) {
            throw new ForbiddenException("You don't have permission for this action.");
        }
        for (AccessLevel level : levels) {
            if (principal.accessLevel() == level) {
                return;
            }
        }
        throw new ForbiddenException("You don't have permission for this action.");
    }

    public void requirePlatformAccess(AuthenticatedPrincipal principal) {
        requireAccessLevel(principal, AccessLevel.PLATFORM_ADMIN, AccessLevel.PLATFORM_TEAM);
    }

    public void requirePlatformAdmin(AuthenticatedPrincipal principal) {
        requireAccessLevel(principal, AccessLevel.PLATFORM_ADMIN);
    }

    public void requireService(AuthenticatedPrincipal principal, String serviceId) {
        if (principal.isPlatformAdmin()) {
            return;
        }
        if (!principal.hasService(serviceId)) {
            throw new ForbiddenException("You don't have access to this service.");
        }
    }

    public void requireTenantAccess(AuthenticatedPrincipal principal, String tenantId) {
        if (principal.isPlatformAdmin() || principal.accessLevel() == AccessLevel.PLATFORM_TEAM) {
            return;
        }
        if (principal.tenantId() == null || !principal.tenantId().equals(tenantId)) {
            throw new ForbiddenException("You don't have access to this tenant.");
        }
        if (!PLATFORM_LEVELS.contains(principal.accessLevel())
                && principal.accessLevel() != AccessLevel.BUSINESS_OWNER
                && principal.accessLevel() != AccessLevel.BUSINESS_MEMBER) {
            throw new ForbiddenException("You don't have permission for this tenant.");
        }
    }

    public void requireTenantEditor(AuthenticatedPrincipal principal, String tenantId) {
        requireTenantAccess(principal, tenantId);
        if (principal.isPlatformUser()) {
            return;
        }
        if (principal.accessLevel() == AccessLevel.BUSINESS_OWNER) {
            return;
        }
        if (principal.businessRole() == null || !EDIT_ROLES.contains(principal.businessRole())) {
            throw new ForbiddenException("You don't have permission to edit this tenant.");
        }
    }

    public void requireTenantAdmin(AuthenticatedPrincipal principal, String tenantId) {
        requireTenantAccess(principal, tenantId);
        if (principal.isPlatformUser()) {
            return;
        }
        if (principal.accessLevel() == AccessLevel.BUSINESS_OWNER) {
            return;
        }
        if (principal.businessRole() == null || !ADMIN_ROLES.contains(principal.businessRole())) {
            throw new ForbiddenException("You don't have permission to manage this tenant.");
        }
    }

    public void requireTenantView(AuthenticatedPrincipal principal, String tenantId) {
        requireTenantAccess(principal, tenantId);
        if (principal.isPlatformUser()) {
            return;
        }
        if (principal.accessLevel() == AccessLevel.BUSINESS_OWNER) {
            return;
        }
        if (principal.businessRole() == null || !VIEW_ROLES.contains(principal.businessRole())) {
            throw new ForbiddenException("You don't have permission for this tenant.");
        }
    }
}
