"""PostgreSQL connection for portals sharing the same writer and config pool."""
import psycopg
from contextlib import contextmanager

Error = psycopg.Error
Unavailable = psycopg.OperationalError


class Row(dict):
    """Match the two forms of access supported by sqlite3.Row."""

    def __init__(self, names, values):
        super().__init__(zip(names, values))
        self.values_by_position = values

    def __getitem__(self, key):
        if isinstance(key, int):
            return self.values_by_position[key]
        return super().__getitem__(key)


def row_factory(cursor):
    names = [col.name for col in cursor.description or ()]
    return lambda values: Row(names, values)


class Connection:
    def __init__(self, dsn):
        self.conn = psycopg.connect(
            dsn, autocommit=True, row_factory=row_factory,
            target_session_attrs="read-write", connect_timeout=3,
        )

    def execute(self, query, args=()):
        # Callers use fixed SQL statements with ? placeholders. Values are bound separately.
        return self.conn.execute(query.replace("?", "%s"), args or None)

    def close(self):
        self.conn.close()

    def begin_write(self):
        self.execute("BEGIN")
        try:
            self.execute("SELECT pg_advisory_xact_lock(9172469)")
        except BaseException:
            self.execute("ROLLBACK")
            raise

    @contextmanager
    def write_transaction(self):
        with self.conn.transaction():
            self.execute("SELECT pg_advisory_xact_lock(9172469)")
            yield

    @contextmanager
    def read_snapshot(self):
        with self.conn.transaction():
            self.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            yield
