CREATE TABLE users (
    user_name VARCHAR(256) PRIMARY KEY,
    phash VARCHAR(512) NOT NULL,
    enabled BOOLEAN DEFAULT true 
);