-- PostgreSQL Schema for TalkIO Authentication Service

-- Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "citext";

-- Schema for authentication related tables
CREATE SCHEMA auth;

-- =============================================
-- Core Authentication Tables
-- =============================================

-- Users table - minimal information needed for authentication
CREATE TABLE auth.users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    external_id VARCHAR(255) NULL UNIQUE,  -- For linking with User Management service
    username CITEXT UNIQUE NULL,  -- NULL for SSO-only users
    email CITEXT UNIQUE NOT NULL,
    password_hash VARCHAR(255) NULL,  -- NULL for SSO-only users
    password_updated_at TIMESTAMPTZ NULL,
    password_reset_required BOOLEAN DEFAULT FALSE,
    failed_login_attempts INTEGER DEFAULT 0,
    last_failed_attempt TIMESTAMPTZ NULL,
    account_locked_until TIMESTAMPTZ NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    email_verification_token VARCHAR(255) NULL,
    email_verification_sent_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ NULL,
    requires_mfa BOOLEAN DEFAULT FALSE,
    auth_provider VARCHAR(50) DEFAULT 'local',  -- 'local', 'google', 'microsoft', 'apple', 'lti', etc.
    user_state VARCHAR(50) DEFAULT 'registered', 
    last_login_ip INET NULL,
    last_user_agent TEXT NULL,
    data_region VARCHAR(50) DEFAULT 'us-east',
    deletion_scheduled_at TIMESTAMPTZ NULL,
    CONSTRAINT valid_auth_provider CHECK (auth_provider IN 
        ('local', 'google', 'microsoft', 'apple', 'facebook', 'lti', 'saml', 'ldap', 'custom')),
    CONSTRAINT valid_user_state CHECK (user_state IN 
        ('registered', 'verified','active','incomplete','disabled','locked','deleted'))
);

-- Create index on fields commonly used in auth queries
CREATE INDEX idx_users_email ON auth.users(email);
CREATE INDEX idx_users_username ON auth.users(username);
CREATE INDEX idx_users_external_id ON auth.users(external_id);
CREATE INDEX idx_users_auth_provider ON auth.users(auth_provider);

-- User roles - simplified RBAC for authentication service
CREATE TABLE auth.roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    role_name VARCHAR(50) NOT NULL UNIQUE,
    description TEXT NULL,
    is_system_role BOOLEAN DEFAULT FALSE,  -- System roles cannot be deleted
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- User-role assignments
CREATE TABLE auth.user_roles (
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES auth.roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    assigned_by UUID NULL REFERENCES auth.users(id) ON DELETE SET NULL,
    PRIMARY KEY (user_id, role_id)
);

-- Sessions for users (when not using JWT-only approach)
CREATE TABLE auth.sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    refresh_token_hash VARCHAR(255) NOT NULL,
    device_identifier VARCHAR(255) NULL,
    device_name VARCHAR(255) NULL,
    device_type VARCHAR(50) NULL,  -- 'mobile', 'desktop', 'tablet', etc.
    ip_address INET NULL,
    user_agent TEXT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_active_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_revoked BOOLEAN DEFAULT FALSE,
    revoked_reason VARCHAR(50) NULL,
    revoked_at TIMESTAMPTZ NULL
);

CREATE INDEX idx_sessions_user_id ON auth.sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON auth.sessions(expires_at);
CREATE INDEX idx_sessions_refresh_token_hash ON auth.sessions(refresh_token_hash);

-- Token blacklist for immediate revocation of JWTs if needed
CREATE TABLE auth.token_blacklist (
    jti UUID PRIMARY KEY,  -- JWT ID that's been revoked
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_by UUID NULL REFERENCES auth.users(id) ON DELETE SET NULL,
    reason VARCHAR(50) NULL
);

CREATE INDEX idx_token_blacklist_expires_at ON auth.token_blacklist(expires_at);
CREATE INDEX idx_token_blacklist_user_id ON auth.token_blacklist(user_id);

-- =============================================
-- Multi-Factor Authentication Tables
-- =============================================

-- MFA methods for users
CREATE TABLE auth.mfa_methods (
    method_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    method_type VARCHAR(20) NOT NULL,  -- 'totp', 'sms', 'email', 'recovery'
    identifier VARCHAR(255) NULL,  -- phone number for SMS, email for email-based OTP
    secret VARCHAR(255) NULL,  -- encrypted TOTP secret or hashed backup codes
    enabled BOOLEAN DEFAULT TRUE,
    last_used_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    verified BOOLEAN DEFAULT FALSE,
    verification_attempts INTEGER DEFAULT 0,
    CONSTRAINT valid_method_type CHECK (method_type IN ('totp', 'sms', 'email', 'recovery'))
);

CREATE INDEX idx_mfa_methods_user_id ON auth.mfa_methods(user_id);
CREATE UNIQUE INDEX idx_mfa_methods_user_method ON auth.mfa_methods(user_id, method_type) 
    WHERE method_type IN ('totp', 'sms', 'email'); -- Allow multiple recovery methods

-- Recovery codes for users (when not stored in mfa_methods)
CREATE TABLE auth.recovery_codes (
    code_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    code_hash VARCHAR(255) NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    used_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_recovery_codes_user_id ON auth.recovery_codes(user_id);

-- =============================================
-- OAuth and External Provider Tables
-- =============================================

-- External identity connections
CREATE TABLE auth.identity_providers (
    provider_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    provider_name VARCHAR(50) NOT NULL UNIQUE,  -- 'google', 'microsoft', etc.
    display_name VARCHAR(100) NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    client_id VARCHAR(255) NULL, -- Encrypted or refers to secret store
    client_secret VARCHAR(255) NULL, -- Encrypted or refers to secret store
    auth_url TEXT NULL,
    token_url TEXT NULL,
    userinfo_url TEXT NULL,
    jwks_uri TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    icon_url TEXT NULL,
    sort_order INTEGER DEFAULT 0,
    domain_restrictions TEXT[] NULL -- Optional domain restrictions
);

-- Individual user connections to identity providers
CREATE TABLE auth.user_identities (
    identity_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    provider_id UUID NOT NULL REFERENCES auth.identity_providers(provider_id) ON DELETE CASCADE,
    provider_user_id VARCHAR(255) NOT NULL,  -- ID from the external provider
    provider_email CITEXT NULL,
    provider_username VARCHAR(255) NULL,
    access_token TEXT NULL,  -- Consider secure storage alternatives
    refresh_token TEXT NULL,  -- Consider secure storage alternatives
    token_expires_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ NULL,
    UNIQUE(provider_id, provider_user_id)
);

CREATE INDEX idx_user_identities_user_id ON auth.user_identities(user_id);
CREATE INDEX idx_user_identities_provider_email ON auth.user_identities(provider_email);

-- =============================================
-- Education-Specific Tables
-- =============================================

-- Educational organization/tenant settings
CREATE TABLE auth.education_tenants (
    tenant_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_name VARCHAR(255) NOT NULL,
    domain VARCHAR(255) NOT NULL UNIQUE,
    password_policy_id UUID NULL,  -- Can point to custom password policy
    mfa_required_roles TEXT[] NULL,  -- Array of role names requiring MFA
    session_timeout_minutes INTEGER DEFAULT 120,
    allow_student_registration BOOLEAN DEFAULT FALSE,
    allow_parent_access BOOLEAN DEFAULT TRUE,
    lti_enabled BOOLEAN DEFAULT FALSE,
    lti_consumer_key VARCHAR(255) NULL,
    lti_shared_secret VARCHAR(255) NULL,  -- Encrypted
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- LTI context mappings
CREATE TABLE auth.lti_contexts (
    context_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES auth.education_tenants(tenant_id) ON DELETE CASCADE,
    lti_context_id VARCHAR(255) NOT NULL,
    lti_context_label VARCHAR(255) NULL,
    lti_context_title VARCHAR(255) NULL,
    external_course_id VARCHAR(255) NULL,  -- Maps to external course ID
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, lti_context_id)
);

CREATE INDEX idx_lti_contexts_tenant ON auth.lti_contexts(tenant_id);

-- =============================================
-- Audit and Security Tables
-- =============================================

-- Security events log
CREATE TABLE auth.security_events (
    event_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type VARCHAR(50) NOT NULL,  -- 'login', 'logout', 'password_change', etc.
    user_id UUID NULL REFERENCES auth.users(id) ON DELETE SET NULL,
    ip_address INET NULL,
    user_agent TEXT NULL,
    device_identifier VARCHAR(255) NULL,
    event_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    success BOOLEAN NOT NULL,
    failure_reason VARCHAR(255) NULL,
    metadata JSONB NULL  -- Additional event-specific data
);

CREATE INDEX idx_security_events_user_id ON auth.security_events(user_id);
CREATE INDEX idx_security_events_timestamp ON auth.security_events(event_timestamp);
CREATE INDEX idx_security_events_type ON auth.security_events(event_type);

-- IP-based security rules
CREATE TABLE auth.ip_rules (
    rule_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ip_address INET NULL,
    ip_range CIDR NULL,
    rule_type VARCHAR(20) NOT NULL,  -- 'allow', 'block', 'mfa_required'
    reason TEXT NULL,
    created_by UUID NULL REFERENCES auth.users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NULL,
    CONSTRAINT valid_rule_type CHECK (rule_type IN ('allow', 'block', 'mfa_required')),
    CONSTRAINT ip_or_range CHECK (
        (ip_address IS NOT NULL AND ip_range IS NULL) OR
        (ip_address IS NULL AND ip_range IS NOT NULL)
    )
);

CREATE INDEX idx_ip_rules_ip_address ON auth.ip_rules(ip_address);
CREATE INDEX idx_ip_rules_ip_range ON auth.ip_rules USING GIST (ip_range inet_ops);

-- Password policies
CREATE TABLE auth.password_policies (
    policy_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    policy_name VARCHAR(100) NOT NULL UNIQUE,
    min_length INTEGER NOT NULL DEFAULT 8,
    require_uppercase BOOLEAN NOT NULL DEFAULT TRUE,
    require_lowercase BOOLEAN NOT NULL DEFAULT TRUE,
    require_numbers BOOLEAN NOT NULL DEFAULT TRUE,
    require_special BOOLEAN NOT NULL DEFAULT TRUE,
    prevent_common_passwords BOOLEAN NOT NULL DEFAULT TRUE,
    prevent_personal_info BOOLEAN NOT NULL DEFAULT TRUE,
    password_history_count INTEGER NOT NULL DEFAULT 5,
    max_age_days INTEGER NULL,  -- NULL for no expiration
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Password history for preventing reuse
CREATE TABLE auth.password_history (
    history_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_password_history_user_id ON auth.password_history(user_id);

-- =============================================
-- Additional Indices for Performance
-- =============================================

-- Expiration indices for cleanup jobs
CREATE INDEX idx_users_deletion_scheduled ON auth.users(deletion_scheduled_at) 
    WHERE deletion_scheduled_at IS NOT NULL;

-- Composite indices for common query patterns
CREATE INDEX idx_users_provider_email ON auth.users(auth_provider, email);
CREATE INDEX idx_sessions_user_active ON auth.sessions(user_id, is_revoked) 
    WHERE is_revoked = FALSE;

-- =============================================
-- Initial Data
-- =============================================

-- Insert default password policy
INSERT INTO auth.password_policies (policy_name, min_length)
VALUES ('Default Policy', 8);

-- Insert default roles
INSERT INTO auth.roles (role_name, description, is_system_role)
VALUES 
('system_admin', 'System Administrator with full access', TRUE),
('tenant_admin', 'Educational Institution Administrator', TRUE),
('teacher', 'Teacher/Instructor role', TRUE),
('student', 'Student role', TRUE),
('parent', 'Parent/Guardian role', TRUE),
('staff', 'School staff member', TRUE);

-- =============================================
-- Functions and Triggers
-- =============================================

-- Update timestamp function
CREATE OR REPLACE FUNCTION update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply update timestamp triggers to relevant tables
CREATE TRIGGER update_users_timestamp
BEFORE UPDATE ON auth.users
FOR EACH ROW EXECUTE FUNCTION update_timestamp();

CREATE TRIGGER update_roles_timestamp
BEFORE UPDATE ON auth.roles
FOR EACH ROW EXECUTE FUNCTION update_timestamp();

-- Audit trigger for password changes
CREATE OR REPLACE FUNCTION audit_password_change()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.password_hash IS DISTINCT FROM NEW.password_hash THEN
        INSERT INTO auth.password_history (user_id, password_hash)
        VALUES (NEW.user_id, NEW.password_hash);
        
        INSERT INTO auth.security_events (event_type, user_id, success)
        VALUES ('password_change', NEW.user_id, TRUE);
        
        NEW.password_updated_at = NOW();
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_password_change_trigger
BEFORE UPDATE ON auth.users
FOR EACH ROW
WHEN (OLD.password_hash IS DISTINCT FROM NEW.password_hash)
EXECUTE FUNCTION audit_password_change();

-- Function to check for password reuse
CREATE OR REPLACE FUNCTION check_password_reuse(
    p_user_id UUID,
    p_new_hash VARCHAR,
    p_history_count INTEGER DEFAULT 5
) RETURNS BOOLEAN AS $$
DECLARE
    matches INTEGER;
BEGIN
    -- This is simplified and would need actual password verification logic in a real implementation
    SELECT COUNT(*) INTO matches
    FROM (
        SELECT password_hash
        FROM auth.password_history
        WHERE user_id = p_user_id
        ORDER BY created_at DESC
        LIMIT p_history_count
    ) recent_passwords
    WHERE password_hash = p_new_hash;
    
    RETURN matches > 0;
END;
$$ LANGUAGE plpgsql;

-- Create session activity tracking function
CREATE OR REPLACE FUNCTION update_session_activity()
RETURNS TRIGGER AS $$
BEGIN
    NEW.last_active_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_session_activity_trigger
BEFORE UPDATE ON auth.sessions
FOR EACH ROW EXECUTE FUNCTION update_session_activity();

-- Function to clean expired sessions
CREATE OR REPLACE FUNCTION clean_expired_sessions()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM auth.sessions
    WHERE expires_at < NOW();
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to clean expired blacklisted tokens
CREATE OR REPLACE FUNCTION clean_expired_blacklist_tokens()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM auth.token_blacklist
    WHERE expires_at < NOW();
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Grant appropriate permissions
GRANT USAGE ON SCHEMA auth TO talkio_auth_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA auth TO talkio_auth_service;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA auth TO talkio_auth_service;
