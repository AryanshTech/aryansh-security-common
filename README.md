# aryansh-security-common

Shared Firebase JWT authentication for Aryansh Tech microservices.

## Install locally

```bash
mvn install
```

Other services reference `com.aryansh:aryansh-security-common:1.0.0`.

## Claims

| Claim | Values |
|-------|--------|
| `accessLevel` | `platform_admin`, `platform_team`, `business_owner`, `business_member` |
| `tenantId` | Tenant ID for business users |
| `businessRole` | `admin`, `editor`, `viewer` (business members only) |
| `services` | Array of service IDs e.g. `business-manager`, `marketing-hub` |

Legacy `role` claim is still read for backward compatibility during migration.
