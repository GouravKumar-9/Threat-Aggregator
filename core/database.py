import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'threat_data.db')


def get_connection():
    """Returns a sqlite3 connection, ensuring the data directory exists."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    return sqlite3.connect(DB_PATH)


def init_db():
    """Initializes the database table if it doesn't exist."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_value TEXT UNIQUE,
            ioc_type TEXT,
            source TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Check for existing columns to support upgrades
    cursor.execute("PRAGMA table_info(iocs)")
    columns = [col[1] for col in cursor.fetchall()]
    if "confidence_score" not in columns:
        cursor.execute("ALTER TABLE iocs ADD COLUMN confidence_score INTEGER DEFAULT 50")
    if "last_seen" not in columns:
        cursor.execute("ALTER TABLE iocs ADD COLUMN last_seen DATETIME")
    if "stix_data" not in columns:
        cursor.execute("ALTER TABLE iocs ADD COLUMN stix_data TEXT")
    if "lat" not in columns:
        cursor.execute("ALTER TABLE iocs ADD COLUMN lat REAL")
    if "lon" not in columns:
        cursor.execute("ALTER TABLE iocs ADD COLUMN lon REAL")
        
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            mfa_secret TEXT
        )
    ''')

    # Create indexes for performance optimization
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_iocs_timestamp ON iocs (timestamp DESC)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_iocs_source ON iocs (source)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs (ioc_type)')

    conn.commit()
    conn.close()


def insert_iocs(ioc_list):
    """Inserts a list of IoC dictionaries into the database using UPSERT. Returns count of processed records."""
    conn = get_connection()
    cursor = conn.cursor()
    from core.normalization import normalize_to_stix
    from core.geoip import fetch_geoip_batch

    # Extract all IPs for batch GeoIP lookup
    ips_to_lookup = [ioc['ioc_value'] for ioc in ioc_list if ioc['ioc_type'] == 'IP']
    
    # We batch in chunks of 100 max per the ip-api rules
    geoip_data = {}
    for i in range(0, len(ips_to_lookup), 100):
        chunk = ips_to_lookup[i:i+100]
        geoip_data.update(fetch_geoip_batch(chunk))

    for ioc in ioc_list:
        stix_data = normalize_to_stix(ioc['ioc_value'], ioc['ioc_type'], ioc['source'])
        
        lat = None
        lon = None
        if ioc['ioc_type'] == 'IP' and ioc['ioc_value'] in geoip_data:
            lat = geoip_data[ioc['ioc_value']]['lat']
            lon = geoip_data[ioc['ioc_value']]['lon']

        try:
            cursor.execute('''
                INSERT INTO iocs (ioc_value, ioc_type, source, stix_data, lat, lon)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(ioc_value) DO UPDATE SET
                    confidence_score = MIN(confidence_score + 10, 100),
                    last_seen = CURRENT_TIMESTAMP,
                    stix_data = excluded.stix_data,
                    lat = COALESCE(iocs.lat, excluded.lat),
                    lon = COALESCE(iocs.lon, excluded.lon)
            ''', (ioc['ioc_value'], ioc['ioc_type'], ioc['source'], stix_data, lat, lon))
        except sqlite3.IntegrityError:
            pass

    conn.commit()
    conn.close()
    return len(ioc_list)

def age_out_iocs():
    """Decreases confidence score and deletes old records (> 7 days)."""
    conn = get_connection()
    cursor = conn.cursor()
    
    # 1. Decrease confidence score by 10 for records not seen in the last 3 days
    cursor.execute('''
        UPDATE iocs SET confidence_score = MAX(confidence_score - 10, 0)
        WHERE last_seen <= datetime('now', '-3 days')
    ''')
    
    # 2. Delete records not seen in the last 7 days and with confidence score <= 10
    cursor.execute('''
        DELETE FROM iocs 
        WHERE last_seen <= datetime('now', '-7 days') AND confidence_score <= 10
    ''')
    
    conn.commit()
    conn.close()


def search_ioc(ioc_value):
    """Searches the database for a specific IoC. Returns a tuple or None."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT ioc_value, ioc_type, source, timestamp FROM iocs WHERE ioc_value = ?',
        (ioc_value,)
    )
    result = cursor.fetchone()
    conn.close()
    return result


def get_all_iocs(limit: int = 50, offset: int = 0):
    """
    Returns a paginated list of all IoCs, newest first.
    Each row is a dict with keys: id, ioc_value, ioc_type, source, timestamp.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT id, ioc_value, ioc_type, source, timestamp, confidence_score, last_seen, stix_data FROM iocs '
        'ORDER BY timestamp DESC LIMIT ? OFFSET ?',
        (limit, offset)
    )
    rows = cursor.fetchall()
    conn.close()
    return [
        {
            "id": r[0],
            "ioc_value": r[1],
            "ioc_type": r[2],
            "source": r[3],
            "timestamp": r[4],
            "confidence_score": r[5],
            "last_seen": r[6],
            "stix_data": r[7]
        }
        for r in rows
    ]


def get_total_count():
    """Returns the total number of IoCs in the database."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM iocs')
    count = cursor.fetchone()[0]
    conn.close()
    return count


def get_recent_iocs(n: int = 20):
    """Returns the N most recently inserted IoCs."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT id, ioc_value, ioc_type, source, timestamp FROM iocs '
        'ORDER BY timestamp DESC LIMIT ?',
        (n,)
    )
    rows = cursor.fetchall()
    conn.close()
    return [
        {
            "id": r[0],
            "ioc_value": r[1],
            "ioc_type": r[2],
            "source": r[3],
            "timestamp": r[4],
        }
        for r in rows
    ]


def get_stats():
    """
    Returns aggregated statistics for the dashboard:
    - total: total IoC count
    - by_source: list of {source, count} sorted by count desc (top 10)
    - by_type: list of {ioc_type, count}
    - daily_trend: list of {date, count} for the last 14 days
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Total count
    cursor.execute('SELECT COUNT(*) FROM iocs')
    total = cursor.fetchone()[0]

    # Count by source (top 10)
    cursor.execute(
        'SELECT source, COUNT(*) as cnt FROM iocs '
        'GROUP BY source ORDER BY cnt DESC LIMIT 10'
    )
    by_source = [{"source": r[0], "count": r[1]} for r in cursor.fetchall()]

    # Count by type
    cursor.execute(
        'SELECT ioc_type, COUNT(*) as cnt FROM iocs GROUP BY ioc_type ORDER BY cnt DESC'
    )
    by_type = [{"ioc_type": r[0], "count": r[1]} for r in cursor.fetchall()]

    # Daily trend — last 14 days
    cursor.execute(
        '''SELECT DATE(timestamp) as day, COUNT(*) as cnt
           FROM iocs
           WHERE timestamp >= DATE('now', '-14 days')
           GROUP BY day
           ORDER BY day ASC'''
    )
    daily_trend = [{"date": r[0], "count": r[1]} for r in cursor.fetchall()]

    conn.close()
    return {
        "total": total,
        "by_source": by_source,
        "by_type": by_type,
        "daily_trend": daily_trend,
    }

# ---------------------------------------------------------------------------
# User Management (Auth/MFA)
# ---------------------------------------------------------------------------

def get_user_by_username(username: str):
    """Returns a user dict by username."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT id, username, password_hash, mfa_secret FROM users WHERE username = ?',
        (username,)
    )
    row = cursor.fetchone()
    conn.close()
    if row:
        return {
            "id": row[0],
            "username": row[1],
            "password_hash": row[2],
            "mfa_secret": row[3]
        }
    return None

def create_user(username: str, password_hash: str):
    """Creates a new user and returns their ID."""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            'INSERT INTO users (username, password_hash) VALUES (?, ?)',
            (username, password_hash)
        )
        user_id = cursor.lastrowid
        conn.commit()
    except sqlite3.IntegrityError:
        user_id = None
    finally:
        conn.close()
    return user_id

def set_user_mfa_secret(user_id: int, secret: str):
    """Updates the MFA secret for a user."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        'UPDATE users SET mfa_secret = ? WHERE id = ?',
        (secret, user_id)
    )
    conn.commit()
    conn.close()