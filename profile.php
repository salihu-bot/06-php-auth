<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

require_login();
$user = current_user();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_verify()) {
        flash('error', 'Your form session expired. Please try again.');
        redirect(app_url('profile.php'));
    }

    $form = $_POST['form'] ?? '';

    if ($form === 'profile') {
        $name = $_POST['name'] ?? '';
        $email = $_POST['email'] ?? '';
        $name = is_string($name) ? trim($name) : '';
        $email = is_string($email) ? strtolower(trim($email)) : '';
        $nameLength = preg_match_all('/[\s\S]/u', $name);

        $errors = [];
        if ($name === '' || $nameLength === false || $nameLength > 100) {
            $errors[] = 'Enter a name of no more than 100 characters.';
        }
        if (filter_var($email, FILTER_VALIDATE_EMAIL) === false || strlen($email) > 160) {
            $errors[] = 'Enter a valid email address (maximum 160 characters).';
        }

        if ($errors === []) {
            $findEmail = db()->prepare('SELECT id FROM users WHERE email = :email AND id <> :id LIMIT 1');
            $findEmail->execute([
                'email' => $email,
                'id' => $user['id'],
            ]);

            if ($findEmail->fetch() !== false) {
                $errors[] = 'An account with that email address already exists.';
            } else {
                try {
                    $update = db()->prepare('UPDATE users SET name = :name, email = :email WHERE id = :id');
                    $update->execute([
                        'name' => $name,
                        'email' => $email,
                        'id' => $user['id'],
                    ]);
                } catch (PDOException $exception) {
                    if (($exception->errorInfo[1] ?? null) !== 1062) {
                        throw $exception;
                    }

                    $errors[] = 'An account with that email address already exists.';
                }

                if ($errors === []) {
                    $_SESSION['user']['name'] = $name;
                    $_SESSION['user']['email'] = $email;
                    flash('status', 'Your profile has been updated.');
                    redirect(app_url('profile.php'));
                }
            }
        }

        $_SESSION['_old_input'] = [
            'name' => $name,
            'email' => $email,
        ];
        flash('errors', $errors);
        redirect(app_url('profile.php'));
    }

    if ($form === 'password') {
        $currentPassword = $_POST['current_password'] ?? '';
        $newPassword = $_POST['new_password'] ?? '';
        $confirmPassword = $_POST['confirm_password'] ?? '';
        $currentPassword = is_string($currentPassword) ? $currentPassword : '';
        $newPassword = is_string($newPassword) ? $newPassword : '';
        $confirmPassword = is_string($confirmPassword) ? $confirmPassword : '';

        $findPassword = db()->prepare('SELECT password_hash FROM users WHERE id = :id LIMIT 1');
        $findPassword->execute(['id' => $user['id']]);
        $passwordHash = $findPassword->fetchColumn();

        if (!is_string($passwordHash) || !password_verify($currentPassword, $passwordHash)) {
            flash('password_error', 'The current password is incorrect.');
            redirect(app_url('profile.php'));
        }

        $newPasswordTooLong = strlen($newPassword) > 72;
        $newPasswordLength = $newPasswordTooLong ? false : preg_match_all('/[\s\S]/u', $newPassword);
        $passwordErrors = [];
        if (
            $newPasswordLength === false
            || $newPasswordTooLong
            || $newPasswordLength < 10
            || preg_match('/\p{L}/u', $newPassword) !== 1
            || preg_match('/\p{N}/u', $newPassword) !== 1
        ) {
            $passwordErrors[] = 'Use a password with at least 10 characters and no more than 72 bytes, including a letter and a number.';
        }
        if ($newPassword !== $confirmPassword) {
            $passwordErrors[] = 'The passwords do not match.';
        }

        if ($passwordErrors !== []) {
            flash('password_errors', $passwordErrors);
            redirect(app_url('profile.php'));
        }

        $newPasswordHash = password_hash($newPassword, PASSWORD_DEFAULT);
        if ($newPasswordHash === false) {
            throw new RuntimeException('Password hashing failed.');
        }

        $updatePassword = db()->prepare('UPDATE users SET password_hash = :password_hash WHERE id = :id');
        $updatePassword->execute([
            'password_hash' => $newPasswordHash,
            'id' => $user['id'],
        ]);

        session_regenerate_id(true);
        unset($_SESSION['_csrf_token']);
        flash('status', 'Your password has been changed.');
        redirect(app_url('profile.php'));
    }

    flash('error', 'Choose a valid profile form.');
    redirect(app_url('profile.php'));
}

$statement = db()->prepare('SELECT name, email FROM users WHERE id = :id LIMIT 1');
$statement->execute(['id' => $user['id']]);
$account = $statement->fetch();
if (!is_array($account)) {
    $_SESSION = [];
    flash('status', 'Your account could not be found. Please sign in again.');
    redirect(app_url('login.php'));
}

$status = flash('status');
$error = flash('error');
$errors = flash('errors');
$passwordError = flash('password_error');
$passwordErrors = flash('password_errors');
$errors = is_array($errors) ? $errors : [];
$passwordErrors = is_array($passwordErrors) ? $passwordErrors : [];
$name = old('name', (string) $account['name']);
$email = old('email', (string) $account['email']);
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Your profile</title>
    <link rel="stylesheet" href="<?= e(app_url('assets/auth.css')) ?>">
</head>
<body>
<?= navbar() ?>
<main class="auth-page">
    <section class="auth-card" aria-labelledby="page-title">
        <p class="eyebrow">Account</p>
        <h1 id="page-title">Your profile</h1>
        <p class="intro">Update your account details or change your password.</p>

        <?php if (is_string($status) && $status !== ''): ?>
            <div class="success-box" role="status"><?= e($status) ?></div>
        <?php endif; ?>
        <?php if (is_string($error) && $error !== ''): ?>
            <div class="error-box" role="alert"><?= e($error) ?></div>
        <?php endif; ?>

        <h2>Account details</h2>
        <?php if ($errors !== []): ?>
            <div class="error-box" role="alert">
                <ul>
                    <?php foreach ($errors as $message): ?>
                        <li><?= e((string) $message) ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>
        <form method="post" action="<?= e(app_url('profile.php')) ?>">
            <?= csrf_field() ?>
            <input type="hidden" name="form" value="profile">
            <label for="name">Name</label>
            <input id="name" name="name" type="text" maxlength="100" autocomplete="name" required value="<?= e($name) ?>">

            <label for="email">Email</label>
            <input id="email" name="email" type="email" maxlength="160" autocomplete="email" required value="<?= e($email) ?>">

            <button type="submit">Save profile</button>
        </form>

        <h2 class="section-heading">Change password</h2>
        <?php if (is_string($passwordError) && $passwordError !== ''): ?>
            <div class="error-box" role="alert"><?= e($passwordError) ?></div>
        <?php endif; ?>
        <?php if ($passwordErrors !== []): ?>
            <div class="error-box" role="alert">
                <ul>
                    <?php foreach ($passwordErrors as $message): ?>
                        <li><?= e((string) $message) ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>
        <form method="post" action="<?= e(app_url('profile.php')) ?>">
            <?= csrf_field() ?>
            <input type="hidden" name="form" value="password">
            <label for="current_password">Current password</label>
            <input id="current_password" name="current_password" type="password" autocomplete="current-password" required>

            <label for="new_password">New password</label>
            <input id="new_password" name="new_password" type="password" autocomplete="new-password" minlength="10" required>
            <p class="field-hint">At least 10 characters, with a letter and a number. Maximum 72 bytes.</p>

            <label for="confirm_password">Confirm new password</label>
            <input id="confirm_password" name="confirm_password" type="password" autocomplete="new-password" required>

            <button type="submit">Change password</button>
        </form>
    </section>
</main>
</body>
</html>
