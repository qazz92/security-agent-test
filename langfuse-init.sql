-- Langfuse Demo Setup: Auto-create user, organization, project, and API keys
-- This allows immediate access to Langfuse web UI without manual setup
-- Note: This script is executed by a separate init container after Langfuse server is ready

-- Step 1: Create demo user with hashed password
-- Password: demo1234 (bcrypt hash)
INSERT INTO users (id, name, email, email_verified, password, created_at, updated_at, admin)
VALUES (
    'demo-user-id-12345',
    'Demo User',
    'demo@example.com',
    NOW(),
    '$2b$10$jBz4QoNOT7tmMqHz30Ye5uKtZaEh4Rh83POSaFZ7WL4TtemP99Iam',  -- bcrypt hash for "demo1234"
    NOW(),
    NOW(),
    true
) ON CONFLICT (email) DO NOTHING;

-- Step 2: Create demo organization
INSERT INTO organizations (id, name, created_at, updated_at)
VALUES (
    'demo-org-id-12345',
    'Security Agent Portfolio',
    NOW(),
    NOW()
) ON CONFLICT (id) DO NOTHING;

-- Step 3: Link user to organization
INSERT INTO organization_memberships (id, org_id, user_id, role, created_at, updated_at)
VALUES (
    'demo-org-membership-id-12345',
    'demo-org-id-12345',
    'demo-user-id-12345',
    'OWNER',
    NOW(),
    NOW()
) ON CONFLICT (org_id, user_id) DO NOTHING;

-- Step 4: Create demo project
INSERT INTO projects (id, name, org_id, created_at, updated_at)
VALUES (
    'demo-project-id-12345',
    'Security Agent Demo',
    'demo-org-id-12345',
    NOW(),
    NOW()
) ON CONFLICT (id) DO NOTHING;

-- Step 5: Link user to project
INSERT INTO project_memberships (project_id, user_id, org_membership_id, role, created_at, updated_at)
VALUES (
    'demo-project-id-12345',
    'demo-user-id-12345',
    'demo-org-membership-id-12345',
    'OWNER',
    NOW(),
    NOW()
) ON CONFLICT (project_id, user_id) DO NOTHING;

-- Step 6: Create demo API keys
-- Public Key: pk-lf-4c97a46c-5cae-4368-b5d1-44939ea97e43
-- Secret Key: sk-lf-4e9dcf62-9cf7-4233-bb5c-d3c3d910fa16
-- (These keys are safe for portfolio demonstration)
INSERT INTO api_keys (
    id,
    created_at,
    note,
    public_key,
    hashed_secret_key,
    fast_hashed_secret_key,
    display_secret_key,
    project_id
)
VALUES (
    'demo-api-key-id-12345',
    NOW(),
    'Demo API Key (Auto-generated)',
    'pk-lf-4c97a46c-5cae-4368-b5d1-44939ea97e43',
    '$2a$11$6HRoXAqWh97Bly4ATDhc2.YeuzRRiEDM63TZ6RMMKHIORVQzDPyNW',
    '576700f4be8ad2137da2754c0f8f3dae0bf37b865a5e7030022970e98e7ed680',
    'sk-lf-****fa16',
    'demo-project-id-12345'
) ON CONFLICT (public_key) DO UPDATE SET
    hashed_secret_key = EXCLUDED.hashed_secret_key,
    fast_hashed_secret_key = EXCLUDED.fast_hashed_secret_key;

-- Print confirmation
DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '==============================================';
    RAISE NOTICE '✅ Langfuse Demo Setup Complete!';
    RAISE NOTICE '==============================================';
    RAISE NOTICE 'Web UI: http://localhost:3001';
    RAISE NOTICE '';
    RAISE NOTICE 'Demo Account:';
    RAISE NOTICE '  Email: demo@example.com';
    RAISE NOTICE '  Password: demo1234';
    RAISE NOTICE '';
    RAISE NOTICE 'API Keys (already configured in .env):';
    RAISE NOTICE '  Public: pk-lf-4c97a46c-5cae-4368-b5d1-44939ea97e43';
    RAISE NOTICE '  Secret: sk-lf-4e9dcf62-9cf7-4233-bb5c-d3c3d910fa16';
    RAISE NOTICE '==============================================';
    RAISE NOTICE '';
END $$;