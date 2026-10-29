<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit("Not found\n");
}

require_once __DIR__ . '/config/db.php';
require_once __DIR__ . '/src/db.php';

if ($argc !== 2) {
    fwrite(STDERR, "Usage: php promote-admin.php email@example.com\n");
    exit(2);
}

$email = strtolower(trim($argv[1]));
if (filter_var($email, FILTER_VALIDATE_EMAIL) === false || strlen($email) > 160) {
    fwrite(STDERR, "Provide a valid email address (maximum 160 characters).\n");
    exit(2);
}

$connection = db();
$findUser = $connection->prepare('SELECT id FROM users WHERE email = :email LIMIT 1');
$findUser->execute(['email' => $email]);
$userId = $findUser->fetchColumn();

if ($userId === false) {
    fwrite(STDERR, "No user account was found for {$email}.\n");
    exit(1);
}

$promote = $connection->prepare('UPDATE users SET role = :role WHERE id = :id');
$promote->execute([
    'role' => 'admin',
    'id' => (int) $userId,
]);

fwrite(STDOUT, "Administrator role granted to {$email}.\n");
