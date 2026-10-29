<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

if (!isset($_SESSION['user']['id'], $_SESSION['user']['name'])) {
    redirect('register.php');
}

$name = is_string($_SESSION['user']['name']) ? $_SESSION['user']['name'] : '';
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Dashboard</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
<main class="auth-page">
    <section class="auth-card" aria-labelledby="page-title">
        <p class="eyebrow">SWD Auth</p>
        <h1 id="page-title">Dashboard</h1>
        <p class="intro">Welcome, <?= e($name) ?>. Your account is ready.</p>
    </section>
</main>
</body>
</html>
