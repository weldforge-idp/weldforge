# Integration: LEAP (Literature Evangelist Administration Program)

**Status:** Active
**Tenant Slug:** `leap`
**Date Added:** 2026-05-22
**Owner:** SDA Conferences

## Overview
LEAP is a centralized platform for activity tracking, stock management, and financial reporting for Literature Evangelism departments across various Seventh-day Adventist Conferences.

## Authentication Details
- **Identity Provider:** WeldForge (Multi-tenant)
- **Tenant:** `leap`
- **Protocol:** OpenID Connect (OIDC) / OAuth 2.1
- **Auth Method:** Authorization Code Flow with PKCE (for mobile/web)

## Roles
Mapped from WeldForge roles to LEAP application roles:
- `DIRECTOR (CPD)`: Full tenant access.
- `ORGANISER (APD)`: Access to multiple assigned fields/teams.
- `TEAM_LEADER (APL)`: Access to own team.
- `LE`: Access to own data only.

## References
- Flyway Migration: `V40__add_leap_tenant.sql`
