# SWD Auth

A PHP 8 authentication example for XAMPP and MySQL. The application uses the
`swd_auth` database with `users` and `login_attempts` tables.

## Setup

1. Start Apache and MySQL from the XAMPP Control Panel.
2. Ensure the `swd_auth` database has the columns used by this application.
   The project's [database.sql](./database.sql) documents the expected schema;
   the application was aligned to the existing XAMPP schema during development.
3. If your local MySQL credentials differ from XAMPP defaults, set `DB_HOST`,
   `DB_NAME`, `DB_USER`, and `DB_PASSWORD` in the Apache/PHP environment.
4. Visit `http://localhost/swd/06-php-auth/register.php` to create the first
   account.
5. Promote an account to administrator from a terminal:

   ```text
   C:\xampp\php\php.exe promote-admin.php me@example.com
   ```

   Run this command from the project directory.

The default database configuration is for a local XAMPP installation
(`127.0.0.1`, database `swd_auth`, user `root`, empty password). Use a dedicated
database account and a strong password outside local development.

## Features

- Registration, login, account profile editing, and password changes.
- Passwords stored with PHP's `password_hash()` API and checked with
  `password_verify()`. Password changes require the current password.
- Session ID rotation after login, registration, and password changes; secure
  session cookie flags and a 30-minute idle timeout.
- CSRF tokens on state-changing forms and POST-only logout.
- Login throttling at five failed attempts per email address or IP in 15
  minutes, with attempt cleanup after successful login.
- Admin role management protected by server-side role checks and CSRF tokens.
- Parameterized PDO queries, HTML output escaping, and a unique email index.
- `X-Frame-Options`, `X-Content-Type-Options`, and `Referrer-Policy` response
  headers.

## Security notes

`bootstrap.php` currently enables PHP error display for local development.
Disable `display_errors` and enable private error logging before deployment.
Serve the application only over HTTPS in production; the session cookie's
`Secure` attribute is enabled when the request uses HTTPS.

The Stage 4 OWASP Top 10 review of the project reported no security findings.
Security reviews are point-in-time assessments and do not replace deployment
hardening or ongoing maintenance.
