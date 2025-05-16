<?php
session_start();
require_once 'config.php';

// Защита от брутфорса
function checkBruteforce($ip) {
    $mysqli = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    // Удаляем старые попытки
    $mysqli->query("DELETE FROM login_attempts WHERE time < DATE_SUB(NOW(), INTERVAL 15 MINUTE)");
    
    $stmt = $mysqli->prepare("SELECT COUNT(*) as attempts FROM login_attempts WHERE ip = ?");
    $stmt->bind_param("s", $ip);
    $stmt->execute();
    $result = $stmt->get_result()->fetch_assoc();
    
    return $result['attempts'] >= 5;
}

function logFailedAttempt($ip) {
    $mysqli = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    $stmt = $mysqli->prepare("INSERT INTO login_attempts (ip, time) VALUES (?, NOW())");
    $stmt->bind_param("s", $ip);
    $stmt->execute();
}

function getEmailsCount() {
    $mysqli = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    $result = $mysqli->query("SELECT COUNT(*) as total FROM users");
    return $result->fetch_assoc()['total'];
}

if (isset($_SESSION['user'])) {
    header('Location: mail.php');
    exit;
}

$error = null;
$total_emails = getEmailsCount();

try {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (checkBruteforce($_SERVER['REMOTE_ADDR'])) {
            throw new Exception('Превышен лимит попыток входа. Подождите 15 минут.');
        }

        $email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
        $password = trim(filter_input(INPUT_POST, 'password', FILTER_UNSAFE_RAW));

        if (!$email || strlen($password) < 1) {
            throw new Exception('Заполните все поля корректно');
        }

        $mysqli = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
        $stmt = $mysqli->prepare("SELECT * FROM users WHERE email = ? LIMIT 1");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();

        if (!$user || $user['assoc_password'] !== $password) {
            logFailedAttempt($_SERVER['REMOTE_ADDR']);
            throw new Exception('Неверный email или пароль');
        }

        $_SESSION['user'] = $email;
        $_SESSION['imap_password'] = $user['imap_password'];
        session_regenerate_id(true);
        
        header('Location: mail.php');
        exit;
    }
} catch (Exception $e) {
    $error = $e->getMessage();
}
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Вход в почту</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2/dist/tailwind.min.css" rel="stylesheet">
</head>
<body class="bg-gray-100">
    <div class="min-h-screen flex items-center justify-center">
        <div class="max-w-md w-full p-8 bg-white rounded-lg shadow-lg">
            <h2 class="text-2xl font-bold text-center mb-8">Вход в почту</h2>
            
            <?php if (isset($error)): ?>
            <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
                <?php echo htmlspecialchars($error); ?>
            </div>
            <?php endif; ?>

            <form method="POST" class="space-y-6">
                <div>
                    <input name="email" type="email" required
                           class="w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500" 
                           placeholder="Email"
                           maxlength="255"
                           autocomplete="email">
                </div>
                <div>
                    <input name="password" type="password" required
                           class="w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500" 
                           placeholder="Пароль"
                           maxlength="100"
                           autocomplete="current-password">
                </div>
                <button type="submit" 
                        class="w-full bg-blue-500 text-white px-4 py-2 rounded-md hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2">
                    Войти
                </button>
            </form>

            <div class="mt-6 text-center text-sm text-gray-600">
                Если у вас возникли проблемы, напишите нам в Telegram: 
                <a href="https://t.me/shopnoname" 
                   class="text-blue-500 hover:text-blue-600" 
                   target="_blank" 
                   rel="noopener noreferrer">@shopnoname</a>
            </div>
            
            <div class="mt-4 text-center text-sm text-gray-500">
                Почтовых ящиков в системе: <?php echo htmlspecialchars($total_emails); ?>
            </div>
        </div>
    </div>
</body>
</html>