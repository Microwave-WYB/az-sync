CREATE TABLE IF NOT EXISTS apkrecord (
    sha256 TEXT PRIMARY KEY,
    sha1 TEXT,
    md5 TEXT,
    dex_date TEXT,
    apk_size INTEGER,
    pkg_name TEXT,
    vercode TEXT,
    vt_detection TEXT,
    vt_scan_date TEXT,
    dex_size INTEGER,
    markets TEXT
);

CREATE INDEX IF NOT EXISTS idx_apkrecord_pkg_name ON apkrecord (pkg_name);
CREATE INDEX IF NOT EXISTS idx_apkrecord_vercode ON apkrecord (vercode);

CREATE TABLE IF NOT EXISTS metadata (
    pkg_name TEXT,
    vercode TEXT,
    data TEXT,
    PRIMARY KEY (pkg_name, vercode)
);

CREATE INDEX IF NOT EXISTS idx_metadata_pkg_name ON metadata (pkg_name);
