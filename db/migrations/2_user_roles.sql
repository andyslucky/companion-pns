CREATE TABLE user_roles (
    user_name VARCHAR(256),
    role_name VARCHAR(256),
    FOREIGN KEY (user_name) REFERENCES Users (user_name) ON DELETE CASCADE,
    PRIMARY KEY (user_name, role_name)
);