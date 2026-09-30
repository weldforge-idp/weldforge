-- ============================================================================
-- V62: a user may hold several tenant roles.
--
-- users.role_id is a single foreign key, so assigning a second role silently
-- replaced the first. That limit pushes adopters toward encoding structure in
-- one role string -- "clepsydra:admin:projectX" -- which makes a
-- tenant-global identifier load-bearing for authorisation inside applications
-- that are not WeldForge.
--
-- The token contract is ALREADY plural: the `roles` claim has always been a
-- JSON array, it simply never held more than one entry plus SUPERADMIN. So
-- this is additive on the wire. No relying party has to change, and no token
-- format breaks.
--
-- users.role_id is deliberately KEPT, as the "primary role" -- the single
-- value the existing UserResponseDto.role / roleId fields report, and what
-- any caller written before today still reads. AdminService is the only
-- writer of both, so they cannot drift.
-- ============================================================================

CREATE TABLE IF NOT EXISTS user_roles (
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id BIGINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- Every token issued reads this by user_id; the primary key covers that
-- lookup already, but the reverse ("who holds this role") is needed when a
-- role is deleted or audited.
CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles (role_id);

-- Backfill: whatever each user holds today becomes their first membership.
-- ON CONFLICT so re-running changes nothing.
INSERT INTO user_roles (user_id, role_id)
SELECT id, role_id FROM users WHERE role_id IS NOT NULL
ON CONFLICT DO NOTHING;

COMMENT ON TABLE user_roles IS
    'Tenant roles held by a user. Source of truth; users.role_id shadows the primary one for callers written before V62.';
