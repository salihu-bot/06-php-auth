<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

if (isset($_SESSION['user']['id'])) {
    redirect('dashboard.php');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = $_POST['name'] ?? '';
    $email = $_POST['email'] ?? '';
    $password = $_POST['password'] ?? '';
    $confirmPassword = $_POST['confirm_password'] ?? '';

    $name = is_string($name) ? trim($name) : '';
    $email = is_string($email) ? strtolower(trim($email)) : '';
    $password = is_string($password) ? $password : '';
    $confirmPassword = is_string($confirmPassword) ? $confirmPassword : '';

    $errors = [];
    $nameLength = preg_match_all('/[\s\S]/u', $name);
    $passwordTooLong = strlen($password) > 72;
    $passwordLength = $passwordTooLong ? false : preg_match_all('/[\s\S]/u', $password);

    if ($name === '' || $nameLength === false || $nameLength > 100) {
        $errors[] = 'Enter a name of no more than 100 characters.';
    }

    if (filter_var($email, FILTER_VALIDATE_EMAIL) === false || strlen($email) > 160) {
        $errors[] = 'Enter a valid email address (maximum 160 characters).';
    }

    if (
        $passwordLength === false
        || $passwordTooLong
        || $passwordLength < 10
        || preg_match('/\p{L}/u', $password) !== 1
        || preg_match('/\p{N}/u', $password) !== 1
    ) {
        $errors[] = 'Use a password with at least 10 characters and no more than 72 bytes, including a letter and a number.';
    }

    if ($password !== $confirmPassword) {
        $errors[] = 'The passwords do not match.';
    }

    if (!csrf_verify()) {
        $errors[] = 'Your form session expired. Please try again.';
    }

    if ($errors === []) {
        $connection = db();
        $existingUser = $connection->prepare('SELECT id FROM users WHERE email = :email LIMIT 1');
        $existingUser->execute(['email' => $email]);

        if ($existingUser->fetch() !== false) {
            $errors[] = 'An account with that email address already exists.';
        } else {
            $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

            if ($hashedPassword === false) {
                throw new RuntimeException('Password hashing failed.');
            }

            try {
                $insertUser = $connection->prepare(
                    'INSERT INTO users (name, email, password_hash) VALUES (:name, :email, :password_hash)'
                );
                $insertUser->execute([
                    'name' => $name,
                    'email' => $email,
                    'password_hash' => $hashedPassword,
                ]);
            } catch (PDOException $exception) {
                if (($exception->errorInfo[1] ?? null) !== 1062) {
                    throw $exception;
                }

                $errors[] = 'An account with that email address already exists.';
            }

            if ($errors === []) {
                session_regenerate_id(true);
                $_SESSION['user'] = [
                    'id' => (int) $connection->lastInsertId(),
                    'name' => $name,
                    'email' => $email,
                ];
                redirect('dashboard.php');
            }
        }
    }

    $_SESSION['_old_input'] = [
        'name' => $name,
        'email' => $email,
    ];
    flash('errors', $errors);
    redirect('register.php');
}

$errors = flash('errors');
$errors = is_array($errors) ? $errors : [];
$name = old('name');
$email = old('email');
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Create account</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
<main class="auth-page">
    <section class="auth-card" aria-labelledby="page-title">
        <p class="eyebrow">SWD Auth</p>
        <h1 id="page-title">Create your account</h1>
        <p class="intro">Register with your name, email, and a secure password.</p>

        <?php if ($errors !== []): ?>
            <div class="error-box" role="alert">
                <p>Please correct the following:</p>
                <ul>
                    <?php foreach ($errors as $error): ?>
                        <li><?= e((string) $error) ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>

        <form method="post" action="register.php">
            <?= csrf_field() ?>
            <label for="name">Name</label>
            <input id="name" name="name" type="text" maxlength="100" autocomplete="name" required value="<?= e($name) ?>">

            <label for="email">Email</label>
            <input id="email" name="email" type="email" maxlength="160" autocomplete="email" required value="<?= e($email) ?>">

            <label for="password">Password</label>
            <input id="password" name="password" type="password" autocomplete="new-password" minlength="10" required>
            <p class="field-hint">At least 10 characters, with a letter and a number. Maximum 72 bytes.</p>

            <label for="confirm_password">Confirm password</label>
            <input id="confirm_password" name="confirm_password" type="password" autocomplete="new-password" required>

            <button type="submit">Create account</button>
        </form>
    </section>
</main>
</body>
</html>
