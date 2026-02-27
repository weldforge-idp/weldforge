-- Roles table
CREATE TABLE IF NOT EXISTS roles (
                                     id BIGSERIAL PRIMARY KEY,
                                     name VARCHAR(50) UNIQUE NOT NULL,
                                     description TEXT
);

-- Users table
CREATE TABLE IF NOT EXISTS users (
                                     id BIGSERIAL PRIMARY KEY,
                                     username VARCHAR(255) UNIQUE NOT NULL,
                                     email VARCHAR(255) UNIQUE NOT NULL,
                                     password VARCHAR(255),
                                     name VARCHAR(255),
                                     image_url VARCHAR(512),
                                     provider VARCHAR(50) NOT NULL,
                                     provider_id VARCHAR(255) NOT NULL,
                                     role_id BIGINT,
                                     created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                                     CONSTRAINT fk_user_role FOREIGN KEY (role_id) REFERENCES roles(id)
);

-- Responsibilities table
CREATE TABLE IF NOT EXISTS responsibilities (
                                                id BIGSERIAL PRIMARY KEY,
                                                name VARCHAR(100) NOT NULL,
                                                role_id BIGINT NOT NULL,
                                                CONSTRAINT fk_responsibility_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

-- Environments table
CREATE TABLE IF NOT EXISTS environments (
                                            id BIGSERIAL PRIMARY KEY,
                                            name VARCHAR(50) NOT NULL,
                                            project_name VARCHAR(100),
                                            description TEXT
);

-- App clients (for x-app-authorization)
CREATE TABLE IF NOT EXISTS app_clients (
                                           id BIGSERIAL PRIMARY KEY,
                                           client_name VARCHAR(100) NOT NULL,
                                           api_key VARCHAR(255) UNIQUE NOT NULL,
                                           enabled BOOLEAN DEFAULT TRUE,
                                           created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
