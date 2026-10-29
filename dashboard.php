<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

require_login();
$user = current_user();

$statement = db()->prepare(
    'SELECT name, email, role, created_at, last_login_at FROM users WHERE id = :id LIMIT 1'
);
$statement->execute(['id' => $user['id']]);
$account = $statement->fetch();

if (!is_array($account)) {
    $_SESSION = [];
    flash('status', 'Your account could not be found. Please sign in again.');
    redirect('login.php');
}

$name = (string) $account['name'];
$lastLogin = $account['last_login_at'] === null
    ? 'Not available'
    : date('F j, Y \a\t g:i a', strtotime((string) $account['last_login_at']));
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
        <p class="intro">Welcome, <?= e($name) ?>. You are signed in.</p>

        <dl class="account-details">
            <div><dt>Name</dt><dd><?= e($name) ?></dd></div>
            <div><dt>Email</dt><dd><?= e((string) $account['email']) ?></dd></div>
            <div><dt>Role</dt><dd><?= e((string) $account['role']) ?></dd></div>
            <div><dt>Member since</dt><dd><?= e(date('F j, Y', strtotime((string) $account['created_at']))) ?></dd></div>
            <div><dt>Last login</dt><dd><?= e($lastLogin) ?></dd></div>
        </dl>

        <form class="logout-form" method="post" action="logout.php">
            <?= csrf_field() ?>
            <button type="submit">Sign out</button>
        </form>
    </section>
</main>
</body>
</html>
