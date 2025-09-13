-- Create databases for different services
CREATE DATABASE auth_service;
CREATE DATABASE hydra;
CREATE DATABASE kratos;

-- Create users with appropriate permissions
CREATE USER auth_user WITH PASSWORD 'auth_password';
CREATE USER hydra_user WITH PASSWORD 'hydra_password';
CREATE USER kratos_user WITH PASSWORD 'kratos_password';

-- Grant permissions
GRANT ALL PRIVILEGES ON DATABASE auth_service TO auth_user;
GRANT ALL PRIVILEGES ON DATABASE hydra TO hydra_user;
GRANT ALL PRIVILEGES ON DATABASE kratos TO kratos_user;

-- Connect to auth_service database and create extensions
\c auth_service;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Connect to hydra database and create extensions
\c hydra;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Connect to kratos database and create extensions
\c kratos;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
