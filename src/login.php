<?php
session_start();
require_once 'config.php';
require_once 'functions.php';

// Защита от брутфорса
function checkLoginAttempts() {
    if (!isset($_SESSION['login_attempts'])) {
        $_SESSION['login_attempts'] = 0;
        $_SESSION['first_attempt'] = time();
    }

    if ((time() - $_SESSION['first_attempt']) > 1800) {
        $_SESSION['login_attempts'] = 0;
        $_SESSION['first_attempt'] = time();
    }

    if ($_SESSION['login_attempts'] >= 5) {
        $waitTime = ceil((1800 - (time() - $_SESSION['first_attempt'])) / 60);
        throw new Exception("Слишком много попыток входа. Попробуйте через {$waitTime} минут.");
    }
}

// Если уже авторизован - редирект в админку
if (isset($_SESSION['admin_id'])) {
    header('Location: admin.php');
    exit;
}

$error = null;

// Обработка формы входа
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        // Проверка попыток входа
        checkLoginAttempts();
        
        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';
        
        if (empty($username) || empty($password)) {
            throw new Exception("Заполните все поля");
        }
        
        $mysqli = getDB();

        // Проверяем существование таблицы admins
        $mysqli->query("
            CREATE TABLE IF NOT EXISTS `admins` (
                `id` int(11) NOT NULL AUTO_INCREMENT,
                `username` varchar(50) NOT NULL,
                `password` varchar(255) NOT NULL,
                `last_login` timestamp NULL DEFAULT NULL,
                `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (`id`),
                UNIQUE KEY `username` (`username`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        ");

        // Если это первый запуск - создаем админа по умолчанию
        $result = $mysqli->query("SELECT COUNT(*) as total FROM admins");
        if ($result && $result->fetch_assoc()['total'] == 0) {
            $default_password = password_hash('admin', PASSWORD_DEFAULT);
            $mysqli->query("INSERT INTO admins (username, password) VALUES ('admin', '{$default_password}')");
        }
        
        // Проверяем учетные данные
        $stmt = $mysqli->prepare("SELECT id, password, last_login FROM admins WHERE username = ? LIMIT 1");
        if (!$stmt) {
            throw new Exception("Системная ошибка");
        }
        
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($admin = $result->fetch_assoc()) {
            if (password_verify($password, $admin['password'])) {
                // Успешный вход
                $_SESSION['admin_id'] = $admin['id'];
                $_SESSION['admin_last_login'] = $admin['last_login'];
                
                // Обновляем время последнего входа
                $stmt = $mysqli->prepare("UPDATE admins SET last_login = NOW() WHERE id = ?");
                $stmt->bind_param("i", $admin['id']);
                $stmt->execute();
                
                // Логируем успешный вход
                $ip = $_SERVER['REMOTE_ADDR'];
                $stmt = $mysqli->prepare("INSERT INTO admin_logs (admin_id, action, ip_address) VALUES (?, 'login', ?)");
                $stmt->bind_param("is", $admin['id'], $ip);
                $stmt->execute();
                
                header('Location: admin.php');
                exit;
            }
        }
        
        // Увеличиваем счетчик попыток
        $_SESSION['login_attempts']++;
        
        // Логируем неудачную попытку входа
        $ip = $_SERVER['REMOTE_ADDR'];
        $stmt = $mysqli->prepare("INSERT INTO admin_logs (admin_id, action, ip_address) VALUES (0, 'login_failed', ?)");
        $stmt->bind_param("s", $ip);
        $stmt->execute();

        throw new Exception("Неверные учетные данные");
        
    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

// Генерируем CSRF токен для формы входа
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <title>Вход в админ-панель</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2/dist/tailwind.min.css" rel="stylesheet">
</head>
<body class="bg-gray-100">
    <div class="min-h-screen flex items-center justify-center">
        <div class="max-w-md w-full space-y-8 p-8 bg-white rounded shadow">
            <h2 class="text-2xl font-bold text-center">Вход в админ-панель</h2>
            
            <?php if (isset($error)): ?>
                <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
                    <?php echo htmlspecialchars($error); ?>
                </div>
            <?php endif; ?>
            
            <form method="POST" class="mt-8 space-y-6" autocomplete="off">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                
                <div>
                    <label class="block text-sm font-medium text-gray-700">Логин</label>
                    <input name="username" type="text" required 
                           class="w-full px-3 py-2 border rounded" 
                           placeholder="Введите логин"
                           pattern="[a-zA-Z0-9]+"
                           title="Только буквы и цифры">
                </div>
                
                <div>
                    <label class="block text-sm font-medium text-gray-700">Пароль</label>
                    <input name="password" type="password" required 
                           class="w-full px-3 py-2 border rounded" 
                           placeholder="Введите пароль">
                </div>
                
                <div>
                    <button type="submit" 
                            class="w-full bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600">
                        Войти
                    </button>
                </div>
            </form>
            
            <div class="text-sm text-center text-gray-600 mt-4">
                По умолчанию: admin / admin
            </div>
        </div>
    </div>
</body>
</html>