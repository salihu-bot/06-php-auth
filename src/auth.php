<?php
declare(strict_types=1);

function current_user(): ?array
{
    $user = $_SESSION['user'] ?? null;

    if (
        !is_array($user)
        || !isset($user['id'], $user['role'])
        || !is_int($user['id'])
        || $user['id'] < 1
        || !is_string($user['role'])
    ) {
        return null;
    }

    return $user;
}

function current_user_role(): ?string
{
    $user = current_user();
    if ($user === null) {
        return null;
    }

    $statement = db()->prepare('SELECT role FROM users WHERE id = :id LIMIT 1');
    $statement->execute(['id' => $user['id']]);
    $role = $statement->fetchColumn();

    if (!is_string($role)) {
        unset($_SESSION['user']);
        return null;
    }

    $_SESSION['user']['role'] = $role;
    return $role;
}

function login_attempt_email_key(string $email): string
{
    return function_exists('mb_substr')
        ? mb_substr($email, 0, 160, 'UTF-8')
        : substr($email, 0, 160);
}

function login_throttle_minutes(string $email, string $ip): int
{
    $statement = db()->prepare(
        'SELECT
            (SELECT COUNT(*) FROM login_attempts
                WHERE email = :email_count AND attempted_at >= DATE_SUB(NOW(), INTERVAL 15 MINUTE)) AS email_failures,
            (SELECT CEIL(TIMESTAMPDIFF(SECOND, NOW(), DATE_ADD(attempted_at, INTERVAL 15 MINUTE)) / 60)
                FROM login_attempts
                WHERE email = :email_wait AND attempted_at >= DATE_SUB(NOW(), INTERVAL 15 MINUTE)
                ORDER BY attempted_at DESC LIMIT 1 OFFSET 4) AS email_wait,
            (SELECT COUNT(*) FROM login_attempts
                WHERE ip = :ip_count AND attempted_at >= DATE_SUB(NOW(), INTERVAL 15 MINUTE)) AS ip_failures,
            (SELECT CEIL(TIMESTAMPDIFF(SECOND, NOW(), DATE_ADD(attempted_at, INTERVAL 15 MINUTE)) / 60)
                FROM login_attempts
                WHERE ip = :ip_wait AND attempted_at >= DATE_SUB(NOW(), INTERVAL 15 MINUTE)
                ORDER BY attempted_at DESC LIMIT 1 OFFSET 4) AS ip_wait'
    );
    $statement->execute([
        'email_count' => login_attempt_email_key($email),
        'email_wait' => login_attempt_email_key($email),
        'ip_count' => $ip,
        'ip_wait' => $ip,
    ]);
    $throttle = $statement->fetch();

    if (!is_array($throttle)) {
        return 0;
    }

    $waitMinutes = 0;
    foreach (['email', 'ip'] as $dimension) {
        if ((int) $throttle[$dimension . '_failures'] >= 5) {
            $waitMinutes = max($waitMinutes, (int) $throttle[$dimension . '_wait']);
        }
    }

    return $waitMinutes > 0 ? $waitMinutes : 0;
}

function record_failed_login(string $email, string $ip): void
{
    $statement = db()->prepare(
        'INSERT INTO login_attempts (email, ip) VALUES (:email, :ip)'
    );
    $statement->execute([
        'email' => login_attempt_email_key($email),
        'ip' => $ip,
    ]);
}

function clear_login_attempts(string $email, string $ip): void
{
    $statement = db()->prepare(
        'DELETE FROM login_attempts WHERE email = :email OR ip = :ip'
    );
    $statement->execute([
        'email' => login_attempt_email_key($email),
        'ip' => $ip,
    ]);
}

function safe_intended_url(?string $url): ?string
{
    if ($url === null || $url === '' || preg_match('/[\x00-\x20\x7f\\\\]/', $url) === 1) {
        return null;
    }

    $parts = parse_url($url);
    if (
        $parts === false
        || isset($parts['scheme'])
        || isset($parts['host'])
        || isset($parts['user'])
        || isset($parts['pass'])
        || isset($parts['fragment'])
        || !isset($parts['path'])
        || $parts['path'] === ''
        || str_starts_with($parts['path'], '/')
    ) {
        return null;
    }

    $decodedPath = rawurldecode($parts['path']);
    if (str_contains($decodedPath, '\\') || str_starts_with($decodedPath, '/')) {
        return null;
    }

    foreach (explode('/', $decodedPath) as $segment) {
        if ($segment === '' || $segment === '.' || $segment === '..') {
            return null;
        }
    }

    return $url;
}

function requested_relative_url(): ?string
{
    $requestUri = $_SERVER['REQUEST_URI'] ?? '';

    if (!is_string($requestUri)) {
        return null;
    }

    $requestParts = parse_url($requestUri);
    if (
        $requestParts === false
        || isset($requestParts['scheme'])
        || isset($requestParts['host'])
        || !isset($requestParts['path'])
    ) {
        return null;
    }

    $requestPath = $requestParts['path'];
    $basePath = app_base_path();

    if (!str_starts_with($requestPath, '/') || str_starts_with($requestPath, '//')) {
        return null;
    }

    if ($basePath !== '' && !str_starts_with($requestPath, $basePath . '/')) {
        return null;
    }

    $relativePath = substr($requestPath, strlen($basePath) + 1);
    $query = $requestParts['query'] ?? '';
    $relativeUrl = $relativePath . ($query !== '' ? '?' . $query : '');

    return safe_intended_url($relativeUrl);
}

function require_login(): void
{
    if (current_user() !== null) {
        return;
    }

    $intendedUrl = requested_relative_url();
    if ($intendedUrl !== null && !in_array($intendedUrl, ['login.php', 'register.php', 'logout.php'], true)) {
        $_SESSION['intended_url'] = $intendedUrl;
    }

    redirect(app_url('login.php'));
}

function require_guest(): void
{
    if (current_user() !== null) {
        redirect('dashboard.php');
    }
}

function require_role(string $role): void
{
    require_login();

    if (current_user_role() !== $role) {
        http_response_code(403);
        echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Access denied</title><link rel="stylesheet" href="' . e(app_url('assets/auth.css')) . '"></head><body><main class="auth-page"><section class="auth-card" aria-labelledby="page-title"><p class="eyebrow">SWD Auth</p><h1 id="page-title">Access denied</h1><p class="intro">You do not have permission to view this page.</p><p><a href="' . e(app_url('dashboard.php')) . '">Return to dashboard</a></p></section></main></body></html>';
        exit;
    }
}
