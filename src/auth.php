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
    $scriptName = $_SERVER['SCRIPT_NAME'] ?? '';

    if (!is_string($requestUri) || !is_string($scriptName)) {
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
    $basePath = str_replace('\\', '/', dirname($scriptName));
    $basePath = $basePath === '/' || $basePath === '.' ? '' : rtrim($basePath, '/');

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

    redirect('login.php');
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

    if (current_user()['role'] !== $role) {
        http_response_code(403);
        exit('Forbidden');
    }
}
