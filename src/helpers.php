<?php
declare(strict_types=1);

function e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function redirect(string $location): void
{
    header('Location: ' . $location);
    exit;
}

function app_base_path(): string
{
    static $basePath = null;
    if ($basePath !== null) {
        return $basePath;
    }

    $appRoot = realpath(dirname(__DIR__));
    $documentRoot = isset($_SERVER['DOCUMENT_ROOT'])
        ? realpath((string) $_SERVER['DOCUMENT_ROOT'])
        : false;

    if ($appRoot === false || $documentRoot === false) {
        $basePath = '';
        return $basePath;
    }

    $appRoot = rtrim(str_replace('\\', '/', $appRoot), '/');
    $documentRoot = rtrim(str_replace('\\', '/', $documentRoot), '/');
    $prefix = $documentRoot === '' ? '/' : $documentRoot . '/';

    if (stripos($appRoot . '/', $prefix) !== 0) {
        $basePath = '';
        return $basePath;
    }

    $relativePath = trim(substr($appRoot, strlen($prefix)), '/');
    $basePath = $relativePath === '' ? '' : '/' . $relativePath;
    return $basePath;
}

function app_url(string $path): string
{
    return app_base_path() . '/' . ltrim($path, '/');
}

function flash(string $key, mixed $value = null): mixed
{
    if ($value !== null) {
        $_SESSION['_flash'][$key] = $value;
        return null;
    }

    $message = $_SESSION['_flash'][$key] ?? null;
    unset($_SESSION['_flash'][$key]);

    if (empty($_SESSION['_flash'])) {
        unset($_SESSION['_flash']);
    }

    return $message;
}

function old(string $key, string $default = ''): string
{
    $value = $_SESSION['_old_input'][$key] ?? $default;
    unset($_SESSION['_old_input'][$key]);

    if (empty($_SESSION['_old_input'])) {
        unset($_SESSION['_old_input']);
    }

    return is_string($value) ? $value : $default;
}

function navbar(): string
{
    if (current_user() === null) {
        return '';
    }

    $html = '<nav class="site-nav" aria-label="Main navigation"><a class="brand" href="' . e(app_url('dashboard.php')) . '">SWD Auth</a><div class="nav-links">';

    if (current_user_role() === 'admin') {
        $html .= '<a href="' . e(app_url('admin/users.php')) . '">Admin</a>';
    }

    $html .= '<form method="post" action="' . e(app_url('logout.php')) . '">'
        . csrf_field()
        . '<button type="submit">Sign out</button></form></div></nav>';

    return $html;
}
