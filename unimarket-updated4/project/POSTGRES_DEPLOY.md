# Render Postgres deployment

The app now uses SQLite locally and Render Postgres automatically when `DATABASE_URL` is present.

## Deploy

1. Commit and deploy this version to the Render web service.
2. In Render Environment, set `DATABASE_URL` to the database's **Internal Database URL**. Keep the database and web service in the same region.
3. Make sure the build command installs `requirements.txt` and the start command is `python server/main.py`.
4. Deploy. On first boot, the app creates the PostgreSQL tables and safe demo accounts.

## Preserve existing SQLite data

If the old Render service has a persistent SQLite file, open the Render Shell after deploying this version and run:

```bash
python migrate_sqlite_to_postgres.py
```

The command reads `database/unimarket.sqlite3`, copies all current records, and advances PostgreSQL identity sequences. It is safe to re-run because rows use `ON CONFLICT DO NOTHING`.

If the old service did not have persistent disk storage, the old SQLite file is not available to migrate. In that case, use the new Postgres database as a fresh database and re-create accounts/listings.

## Verify

After deployment, test registration, login, dashboard navigation, listing creation, chat, orders, and M-Pesa. Do not use the External Database URL inside the Render web service, and never commit `DATABASE_URL` to the repository.
