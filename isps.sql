--
-- File generated with SQLiteStudio v3.1.1 on Вс ноя 18 17:00:09 2018
--
-- Text encoding used: System
--
PRAGMA foreign_keys = off;
BEGIN TRANSACTION;

-- Table: aliases
DROP TABLE IF EXISTS aliases;

CREATE TABLE aliases (
    raliases INTEGER PRIMARY KEY AUTOINCREMENT
                     UNIQUE
                     NOT NULL,
    rdir     INTEGER REFERENCES dir (rdir) ON DELETE CASCADE
                                           ON UPDATE CASCADE
                     NOT NULL,
    alias    TEXT
);


-- Table: ases
DROP TABLE IF EXISTS ases;

CREATE TABLE ases (
    rases INTEGER PRIMARY KEY AUTOINCREMENT
                  UNIQUE
                  NOT NULL,
    rdir  INTEGER REFERENCES dir (rdir) ON DELETE CASCADE
                                        ON UPDATE CASCADE
                  NOT NULL,
    asn   INTEGER UNIQUE
);


-- Table: dir
DROP TABLE IF EXISTS dir;

CREATE TABLE dir (
    rdir INTEGER UNIQUE
                 PRIMARY KEY AUTOINCREMENT
                 NOT NULL,
    name TEXT    NOT NULL
                 UNIQUE
);


COMMIT TRANSACTION;
PRAGMA foreign_keys = on;
