<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

require_guest();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = $_POST['email'] ?? '';
    $password = $_POST['password'] ?? '';
    $email = is_string($email) ? strtolower(trim($email)) : '';
    $password = is_string($password) ? $password : '';

    if (!csrf_verify()) {
        flash('error', 'Your form session expired. Please try again.');
        $_SESSION['_old_input'] = ['email' => $email];
        redirect('login.php');
    }

    $statement = db()->prepare(
        'SELECT id, name, email, password_hash, role FROM users WHERE email = :email LIMIT 1'
    );
    $statement->execute(['email' => $email]);
    $user = $statement->fetch();
    $dummyPasswordHash = '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi';
    $passwordHash = is_array($user) ? $user['password_hash'] : $dummyPasswordHash;
    $passwordIsValid = is_string($passwordHash) && password_verify($password, $passwordHash);

    if (!is_array($user) || !$passwordIsValid) {
        flash('error', 'Invalid email or password');
        $_SESSION['_old_input'] = ['email' => $email];
        redirect('login.php');
    }

    if (password_needs_rehash($passwordHash, PASSWORD_DEFAULT)) {
        $newPasswordHash = password_hash($password, PASSWORD_DEFAULT);
        if ($newPasswordHash === false) {
            throw new RuntimeException('Password rehashing failed.');
        }

        $updatePassword = db()->prepare('UPDATE users SET password_hash = :password_hash WHERE id = :id');
        $updatePassword->execute([
            'password_hash' => $newPasswordHash,
            'id' => (int) $user['id'],
        ]);
    }

    $updateLastLogin = db()->prepare('UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = :id');
    $updateLastLogin->execute(['id' => (int) $user['id']]);

    session_regenerate_id(true);
    unset($_SESSION['_csrf_token'], $_SESSION['_old_input']);
    $_SESSION['user'] = [
        'id' => (int) $user['id'],
        'role' => (string) $user['role'],
        'name' => (string) $user['name'],
        'email' => (string) $user['email'],
    ];
    $_SESSION['_last_activity'] = time();

    $intendedUrl = safe_intended_url(
        isset($_SESSION['intended_url']) && is_string($_SESSION['intended_url'])
            ? $_SESSION['intended_url']
            : null
    );
    unset($_SESSION['intended_url']);

    redirect($intendedUrl ?? 'dashboard.php');
}

$errors = flash('error');
$status = flash('status');
if (($_COOKIE['SWDAUTHFLASH'] ?? null) === 'logged_out') {
    setcookie('SWDAUTHFLASH', '', [
        'expires' => time() - 3600,
        'path' => '/',
        'secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== '' && strtolower((string) $_SERVER['HTTPS']) !== 'off',
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    $status = 'You have been logged out.';
}
$email = old('email');
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Sign in</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
<main class="auth-page">
    <section class="auth-card" aria-labelledby="page-title">
        <p class="eyebrow">SWD Auth</p>
        <h1 id="page-title">Welcome back</h1>
        <p class="intro">Sign in to continue to your account.</p>

        <?php if (is_string($status) && $status !== ''): ?>
            <div class="success-box" role="status"><?= e($status) ?></div>
        <?php endif; ?>

        <?php if (is_string($errors) && $errors !== ''): ?>
            <div class="error-box" role="alert"><?= e($errors) ?></div>
        <?php endif; ?>

        <form method="post" action="login.php">
            <?= csrf_field() ?>
            <label for="email">Email</label>
            <input id="email" name="email" type="email" maxlength="160" autocomplete="username" required value="<?= e($email) ?>">

            <label for="password">Password</label>
            <input id="password" name="password" type="password" autocomplete="current-password" required>

            <button type="submit">Sign in</button>
        </form>

        <p class="auth-links">New here? <a href="register.php">Create an account</a></p>
    </section>
</main>
</body>
</html>
