# 2. SQLite persistence and a single worker

- Status: accepted
- Date: 2026-11-19

## Context

Scan results lived in a module-level dict keyed by a random id. It was fine in
development and wrong everywhere else:

- the report page 404'd intermittently once uvicorn ran more than one worker, because the
  id was written in one process and read in another;
- memory grew with every upload and nothing bounded it;
- restarting the container lost the history, which is the only reason to keep a history.

## Decision

Persist one row per scan in SQLite: `id, filename, vendor, score, grade, findings,
created_at`. The schema is created on startup in the ASGI lifespan. `findings` is stored
as a JSON blob rather than a child table. The database path comes from `NETAUDIT_DB`,
resolved on every connection so tests can point at a throwaway file.

The container runs exactly one uvicorn worker.

## Consequences

- Reports survive restarts and are addressable across processes, which also makes the
  Markdown and SARIF exports independent of the upload request.
- The JSON column keeps the schema at one table. The cost is that I cannot query "all
  FG-001 findings" in SQL; a child table or `json_each` is the escape hatch if I ever need
  that aggregate.
- Write concurrency is serialised by SQLite. With one worker that is a non-issue, and it
  is the reason for the single-worker constraint rather than a consequence of it.
- The compose file mounts `/data` as the only writable path, so the database has to live
  there; `NETAUDIT_DB` is baked into the image for that reason.
- Multi-worker, or any real multi-instance deployment, needs Postgres. Tracked in the
  roadmap; the store is small enough that swapping it is a contained change.
- Tests must isolate the database per run, otherwise they read each other's rows and fail
  in the order pytest happens to collect them.
