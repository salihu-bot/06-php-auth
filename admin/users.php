<?php
declare(strict_types=1);

require_once dirname(__DIR__) . '/bootstrap.php';

require_role('admin');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_verify()) {
        flash('error', 'Your form session expired. Please try again.');
        redirect(app_url('admin/users.php'));
    }

    $userId = filter_var($_POST['user_id'] ?? null, FILTER_VALIDATE_INT);
    $newRole = $_POST['role'] ?? null;

    if (!is_int($userId) || $userId < 1 || !in_array($newRole, ['user', 'admin'], true)) {
        flash('error', 'Choose a valid user and role.');
        redirect(app_url('admin/users.php'));
    }

    $currentUser = current_user();
    if ($currentUser !== null && $userId === $currentUser['id'] && $newRole !== 'admin') {
        flash('error', 'You cannot demote your own account.');
        redirect(app_url('admin/users.php'));
    }

    $update = db()->prepare('UPDATE users SET role = :role WHERE id = :id');
    $update->execute([
        'role' => $newRole,
        'id' => $userId,
    ]);

    if ($update->rowCount() === 0) {
        $check = db()->prepare('SELECT id FROM users WHERE id = :id LIMIT 1');
        $check->execute(['id' => $userId]);

        if ($check->fetchColumn() === false) {
            flash('error', 'That user could not be found.');
            redirect(app_url('admin/users.php'));
        }
    }

    flash('status', 'User role updated.');
    redirect(app_url('admin/users.php'));
}

$status = flash('status');
$error = flash('error');
$users = db()->query(
    'SELECT id, name, email, role, created_at, last_login_at FROM users ORDER BY created_at DESC, id DESC'
)->fetchAll();
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Manage users</title>
    <link rel="stylesheet" href="<?= e(app_url('assets/auth.css')) ?>">
</head>
<body>
<?= navbar() ?>
<main class="auth-page">
    <section class="auth-card admin-card" aria-labelledby="page-title">
        <div class="admin-toolbar">
            <div>
                <p class="eyebrow">Administration</p>
                <h1 id="page-title">Manage users</h1>
            </div>
        </div>

        <?php if (is_string($status) && $status !== ''): ?>
            <div class="success-box" role="status"><?= e($status) ?></div>
        <?php endif; ?>
        <?php if (is_string($error) && $error !== ''): ?>
            <div class="error-box" role="alert"><?= e($error) ?></div>
        <?php endif; ?>

        <div class="table-scroll">
            <table class="users-table">
                <thead>
                <tr>
                    <th>Name</th>
                    <th>Email</th>
                    <th>Role</th>
                    <th>Created</th>
                    <th>Last login</th>
                    <th>Change role</th>
                </tr>
                </thead>
                <tbody>
                <?php foreach ($users as $user): ?>
                    <tr>
                        <td><?= e((string) $user['name']) ?></td>
                        <td><?= e((string) $user['email']) ?></td>
                        <td><?= e((string) $user['role']) ?></td>
                        <td><?= e(date('M j, Y', strtotime((string) $user['created_at']))) ?></td>
                        <td>
                            <?= $user['last_login_at'] === null
                                ? 'Never'
                                : e(date('M j, Y g:i a', strtotime((string) $user['last_login_at']))) ?>
                        </td>
                        <td>
                            <form method="post" action="<?= e(app_url('admin/users.php')) ?>">
                                <?= csrf_field() ?>
                                <input type="hidden" name="user_id" value="<?= (int) $user['id'] ?>">
                                <label class="visually-hidden" for="role-<?= (int) $user['id'] ?>">Role for <?= e((string) $user['name']) ?></label>
                                <select id="role-<?= (int) $user['id'] ?>" name="role">
                                    <option value="user"<?= $user['role'] === 'user' ? ' selected' : '' ?>>User</option>
                                    <option value="admin"<?= $user['role'] === 'admin' ? ' selected' : '' ?>>Admin</option>
                                </select>
                                <button type="submit">Save</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
                <?php if ($users === []): ?>
                    <tr><td colspan="6">No users found.</td></tr>
                <?php endif; ?>
                </tbody>
            </table>
        </div>
    </section>
</main>
</body>
</html>
