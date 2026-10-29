<?php
declare(strict_types=1);

$dbHost = getenv('DB_HOST');
$dbName = getenv('DB_NAME');
$dbUser = getenv('DB_USER');
$dbPassword = getenv('DB_PASSWORD');

define('DB_HOST', $dbHost === false || $dbHost === '' ? '127.0.0.1' : $dbHost);
define('DB_NAME', $dbName === false || $dbName === '' ? 'swd_auth' : $dbName);
define('DB_USER', $dbUser === false ? 'root' : $dbUser);
define('DB_PASSWORD', $dbPassword === false ? '' : $dbPassword);
