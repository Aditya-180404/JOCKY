-- Persist TraceForge source so queued compiler jobs can build the submitted version.
ALTER TABLE tool_versions
    ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT '';
