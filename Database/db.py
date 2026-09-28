import sqlite3
import os 
base_directory = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

Database_path = os.path.join(base_directory,'Data','database.db')
"""
Two tables are created in a database - User accounts and Audit logs
"""
def get_connection():
    connect = sqlite3.connect(Database_path)
     # allows accessing columns by name
    connect.row_factory = sqlite3.Row 
    return connect


def initialise_database():
    os.makedirs(os.path.dirname(Database_path), exist_ok=True)
    connect = get_connection()
    cursor = connect.cursor()

    # Users account table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users(
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   username TEXT UNIQUE NOT NULL,
                   argon2_hash TEXT NOT NULL,
                   role TEXT NOT NULL,
                   revoked INTEGER DEFAULT 0)

    ''')

    # Audit log table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   timestamp TEXT NOT NULL,
                   username TEXT NOT NULL,
                   role TEXT NOT NULL,
                   action TEXT NOT NULL,
                   filename TEXT,
                   previous_hmac TEXT NOT NULL,
                   hmac TEXT NOT NULL)
    ''')

    connect.commit()
    connect.close()


def user_exists(username):
    # User name exists or not 
    connect = get_connection()
    cursor = connect.cursor()
    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    connect.close()
    return result is not None


def insert_user(username, argon2_hash, role):
    #insert user into the table
    connect = get_connection()
    cursor = connect.cursor()
    cursor.execute('''
        INSERT INTO users (username, argon2_hash, role)
        VALUES (?, ?, ?)
    ''', (username, argon2_hash, role))
    connect.commit()
    connect.close()


def get_user(username):
    connect = get_connection()
    cursor = connect.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    connect.close()
    return user


def insert_log_entry(timestamp, username, role, action, filename, previous_hmac, hmac):
    #adding audit entry into the table
    connect = get_connection()
    cursor = connect.cursor()
    cursor.execute('''
        INSERT INTO audit_log (timestamp, username, role, action, filename, previous_hmac, hmac)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, username, role, action, filename, previous_hmac, hmac))
    connect.commit()
    connect.close()


def get_last_log_entry():
    connect = get_connection()
    cursor = connect.cursor()
    cursor.execute('SELECT * FROM audit_log ORDER BY id DESC LIMIT 1')
    entry = cursor.fetchone()
    connect.close()
    return entry


def get_all_log_entries():
    connect = get_connection()
    cursor = connect.cursor()
    cursor.execute('SELECT * FROM audit_log ORDER BY id ASC')
    entries = cursor.fetchall()
    connect.close()
    return entries