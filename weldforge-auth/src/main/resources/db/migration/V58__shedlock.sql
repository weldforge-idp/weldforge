-- ShedLock's lock table: one row per scheduled job, holding whichever instance
-- currently owns it and until when.
--
-- Why this exists: weldforge-auth has eight @Scheduled methods, and Spring runs
-- every one of them on every instance. At one replica that is invisible. At two
-- it means two provisioning retries for the same paid order, two deliveries of
-- the same webhook, and two concurrent signing-key rotations -- so the service
-- could not be scaled horizontally without it, whatever the cluster could
-- afford. See docs/scaling.md.
--
-- The lock lives here rather than in Redis deliberately: every instance already
-- shares this database, so horizontal scaling does not also require standing up
-- and operating another stateful dependency.
--
-- Column names and types are fixed by ShedLock's JdbcTemplateLockProvider.
CREATE TABLE IF NOT EXISTS shedlock (
    name       VARCHAR(64)  NOT NULL,
    lock_until TIMESTAMP    NOT NULL,
    locked_at  TIMESTAMP    NOT NULL,
    locked_by  VARCHAR(255) NOT NULL,
    PRIMARY KEY (name)
);

COMMENT ON TABLE shedlock IS
    'ShedLock coordination table. One row per @SchedulerLock name; a row is a lease, not a queue. Safe to truncate while every instance is stopped.';
