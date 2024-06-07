CREATE TABLE api_tokens(
    user_name VARCHAR(256),
    token_id SERIAL,
    token_description VARCHAR(256) NOT NULL,
    token_expiration TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (user_name, token_id),
    FOREIGN KEY (user_name) REFERENCES Users (user_name) ON DELETE CASCADE
);