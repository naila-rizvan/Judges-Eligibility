-- schema.sql

PRAGMA foreign_keys = ON;

-- Table for membership records
CREATE TABLE IF NOT EXISTS memberships (
    id SERIAL PRIMARY KEY,
    member_id TEXT,
    club_number TEXT,
    club_name TEXT,
    first_name TEXT,
    middle_name TEXT,
    last_name TEXT,
    uploaded_at DATE
);

-- Table to track uploaded files
CREATE TABLE IF NOT EXISTS uploads_meta (
    id SERIAL PRIMARY KEY,
    filename TEXT,
    storage_path TEXT,
    uploaded_at DATE
);
