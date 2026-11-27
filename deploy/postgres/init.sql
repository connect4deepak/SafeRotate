-- Demo database for SafeRotate. The app logs in as one of two roles
-- (app_blue / app_green) that both inherit privileges from the group role app.
CREATE ROLE app NOLOGIN;
CREATE ROLE app_blue LOGIN PASSWORD 'blue-initial-demo-pw' IN ROLE app;
CREATE ROLE app_green NOLOGIN IN ROLE app;

-- SafeRotate's own least-privilege role: it can change only the two app roles.
CREATE ROLE saferotate LOGIN PASSWORD 'saferotate-demo-pw' CREATEROLE;
GRANT app_blue, app_green TO saferotate WITH ADMIN OPTION;

CREATE TABLE items (id serial PRIMARY KEY, name text NOT NULL);
INSERT INTO items (name) SELECT 'item ' || g FROM generate_series(1, 100) g;
GRANT SELECT ON items TO app;
