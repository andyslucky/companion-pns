CREATE TABLE user_devices(
    user_name VARCHAR(256),
    device_id VARCHAR(256),
    device_platform VARCHAR(32),
    PRIMARY KEY (user_name, device_id),
    FOREIGN KEY (user_name) REFERENCES users(user_name)
);
