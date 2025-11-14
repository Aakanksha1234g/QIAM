--1 RBAC tables
CREATE TABLE IF NOT EXISTS users(
    id                  BIGSERIAL PRIMARY KEY,
    kc_id               UUID UNIQUE,
    username             VARCHAR(100) UNIQUE NOT NULL,
    email               VARCHAR(255) UNIQUE NOT NULL,
    full_name           VARCHAR(200),
    status              VARCHAR(20) DEFAULT 'active',
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS roles (
    id       BIGSERIAL primary KEY,
    name     VARCHAR(50) UNIQUE NOT NULL,
    description TEXT
);

CREATE TABLE IF NOT EXISTS permissions (
    id  BIGSERIAL PRIMARY KEY,
    code  VARCHAR(100) UNIQUE NOT NULL,
    description TEXT
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id BIGINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    username VARCHAR(100) UNIQUE NOT NULL,
    user_role VARCHAR(100) UNIQUE NOT NULL
    PRIMARY KEY(user_id, role_id)
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id         BIGINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id   BIGINT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- 2. Seed data
INSERT INTO roles (name,description) VALUES
('student',              'Can view own attendance only'),
('teacher',              'Can mark attendance for own classes'),
('attendance_officer',   'Can view/edit any attendance record'),
('admin',                'Full system access')
ON CONFLICT (name) DO NOTHING;

INSERT INTO permissions (code, description) VALUES
('view_own_attendance',      'See own attendance records'),
('view_class_attendance',    'See attendance of own class'),
('mark_attendance',          'Record presence/absence'),
('edit_any_attendance',      'Modify any attendance record'),
('manage_users',             'Create/edit/delete users'),
('manage_roles',             'Assign roles/permissions')
ON CONFLICT (code) DO NOTHING;

--role - permission links
WITH r AS (SELECT id, name FROM roles),
    p AS (SELECT id, code FROM permissions)
INSERT INTO role_permissions(role_id, permission_id)
SELECT r.id, p.id FROM r,p
WHERE (r.name, p.code) IN (
    ('student', 'view_own_attendance'),
    ('teacher','view_class_attendance'),
    ('teacher','mark_attendance'),
    ('attendance_officer','view_class_attendance'), 
    ('attendance_officer','mark_attendance'),
    ('attendance_officer','edit_any_attendance'),
    ('admin', 'manage_users'),
    ('admin','manage_roles'),
    ('admin','view_class_attendance'),
    ('admin','edit_any_attendance')
)
ON CONFLICT DO NOTHING;

--3. Fast view for permission lookup
CREATE OR REPLACE VIEW user_permissions AS
SELECT DISTINCT u.id AS user_id, p.code FROM users u
JOIN user_roles ur ON ur.user_id = u.id
JOIN role_permissions rp ON rp.role_id = ur.role_id
JOIN permissions p ON p.id = rp.permission_id;