-- schema.sql

PRAGMA foreign_keys = ON;

-- table that stores each membership row; each row = one member in one club
CREATE TABLE IF NOT EXISTS memberships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id TEXT NOT NULL,
    first_name TEXT,
    middle_name TEXT,
    last_name TEXT,
    email TEXT,
    phone TEXT,
    club_number TEXT NOT NULL,
    club_name TEXT,
    uploaded_at TEXT NOT NULL  -- ISO date of the upload that added this row
);

-- a simple table to track latest upload timestamp and filename
CREATE TABLE IF NOT EXISTS uploads_meta (
    id INTEGER PRIMARY KEY,
    filename TEXT,
    uploaded_at TEXT
);
