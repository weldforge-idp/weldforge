-- V40: Add LEAP tenant.
-- This enables the LEAP application to use WeldForge as its identity provider.
INSERT INTO tenants (slug, name, display_name, contact_email)
VALUES ('leap', 'Literature Evangelist Administration Program', 'LEAP', 'admin@leap.tech')
ON CONFLICT (slug) DO NOTHING;
