INSERT INTO app_clients (client_name, api_key, enabled)
VALUES
    ('frontend-admin-portal', 'x-app-auth-1234567890abcdef', TRUE),
    ('mobile-backend', 'x-app-auth-mobile-9876543210fedcba', TRUE)
ON CONFLICT (api_key) DO NOTHING;