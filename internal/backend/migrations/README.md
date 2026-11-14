# SQL migrations

Files are numbered `NNNN_name.sql` and embedded into the backend binary. Each
file is applied once in a transaction, in ascending numeric order. `GO` on its
own line separates batches; the migrator executes each batch separately.
Migration checksums are stored in `schema_migrations`; editing an applied file
is an error. Details and the full schema are added in P04.
