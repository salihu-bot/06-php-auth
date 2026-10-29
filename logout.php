<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    header('Allow: POST');
    exit('Method Not Allowed');
}

if (!csrf_verify()) {
    http_response_code(403);
    exit('Invalid form token.');
}

$cookieParams = session_get_cookie_params();
$sessionCookieName = session_name();
$_SESSION = [];
session_destroy();

if (ini_get('session.use_cookies')) {
    setcookie($sessionCookieName, '', [
        'expires' => time() - 42000,
        'path' => $cookieParams['path'],
        'domain' => $cookieParams['domain'],
        'secure' => $cookieParams['secure'],
        'httponly' => $cookieParams['httponly'],
        'samesite' => $cookieParams['samesite'] ?? 'Lax',
    ]);
}

setcookie('SWDAUTHFLASH', 'logged_out', [
    'expires' => time() + 60,
    'path' => '/',
    'secure' => $cookieParams['secure'],
    'httponly' => true,
    'samesite' => 'Lax',
]);

redirect('login.php');
