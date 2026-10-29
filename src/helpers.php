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
