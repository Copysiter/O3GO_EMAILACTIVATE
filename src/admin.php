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

// Функция безопасного подключения к БД
function getDB() {
    try {
        $mysqli = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
        if ($mysqli->connect_error) {
            throw new Exception('Ошибка подключения к базе данных');
        }
        $mysqli->set_charset("utf8mb4");
        return $mysqli;
    } catch (Exception $e) {
        error_log($e->getMessage());
        throw new Exception('Системная ошибка');
    }
}


// Функция для получения статистики
function getStats($mysqli) {
    $stats = [
        'total_users' => 0,
        'active_users' => 0,
        'total_emails' => 0,
        'domain_stats' => [],
        'daily_stats' => []
    ];
    
    try {
        // Общее количество пользователей
        $result = $mysqli->query("SELECT COUNT(*) as total FROM users");
        if ($result) {
            $stats['total_users'] = (int)$result->fetch_assoc()['total'];
        }
        
        // Активные пользователи за последние 24 часа
        $result = $mysqli->query("SELECT COUNT(DISTINCT user_id) as active FROM user_stats WHERE last_activity > DATE_SUB(NOW(), INTERVAL 24 HOUR)");
        if ($result) {
            $stats['active_users'] = (int)$result->fetch_assoc()['active'];
        }

        // Статистика по доменам
        $result = $mysqli->query("SELECT domain, email_count FROM email_domain_stats ORDER BY email_count DESC LIMIT 10");
        if ($result) {
            while ($row = $result->fetch_assoc()) {
                $stats['domain_stats'][] = $row;
            }
        }

        // Статистика за последние 30 дней
        $result = $mysqli->query("SELECT date, total_emails, active_users 
                                FROM daily_stats 
                                WHERE date > DATE_SUB(CURDATE(), INTERVAL 30 DAY) 
                                ORDER BY date ASC");
        if ($result) {
            while ($row = $result->fetch_assoc()) {
                $stats['daily_stats'][] = $row;
            }
        }
    } catch (Exception $e) {
        error_log("Error in getStats: " . $e->getMessage());
    }
    
    return $stats;
}

// Функция для пагинации
function getPagination($total, $per_page, $current_page) {
    $total_pages = max(1, ceil($total / $per_page));
    $current_page = max(1, min($current_page, $total_pages));
    
    return [
        'total' => $total,
        'per_page' => $per_page,
        'current_page' => $current_page,
        'total_pages' => $total_pages,
        'offset' => ($current_page - 1) * $per_page
    ];
}

// Проверка и очистка входных данных
function sanitizeInput($data) {
    if (is_array($data)) {
        return array_map('sanitizeInput', $data);
    }
    return htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8');
}


// Проверка авторизации
if (!isset($_SESSION['admin_id'])) {
    // Форма входа
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        try {
            checkLoginAttempts();
            
            $username = sanitizeInput($_POST['username'] ?? '');
            $password = $_POST['password'] ?? '';
            
            if (empty($username) || empty($password)) {
                throw new Exception("Заполните все поля");
            }
            
            $mysqli = getDB();
            
            $stmt = $mysqli->prepare("SELECT id, password_hash, last_login FROM admins WHERE username = ? LIMIT 1");
            if (!$stmt) {
                throw new Exception("Системная ошибка");
            }
            
            $stmt->bind_param("s", $username);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($admin = $result->fetch_assoc()) {
                if (password_verify($password, $admin['password_hash'])) {
                    $_SESSION['admin_id'] = $admin['id'];
                    $_SESSION['admin_last_login'] = $admin['last_login'];
                    
                    // Обновляем время последнего входа
                    $stmt = $mysqli->prepare("UPDATE admins SET last_login = NOW() WHERE id = ?");
                    $stmt->bind_param("i", $admin['id']);
                    $stmt->execute();
                    
                    header('Location: admin.php');
                    exit;
                }
            }
            
            $_SESSION['login_attempts']++;
            throw new Exception("Неверные учетные данные");
            
        } catch (Exception $e) {
            $error = $e->getMessage();
        }
    }
    
    // Генерируем CSRF токен
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }


?>
<!DOCTYPE html>
<html>
<head>
    <title>Вход в админ-панель</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net/; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net/">
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
                    <input name="username" type="text" required 
                           class="w-full px-3 py-2 border rounded" 
                           placeholder="Логин"
                           pattern="[a-zA-Z0-9]+"
                           title="Только буквы и цифры"
                           maxlength="50">
                </div>
                <div>
                    <input name="password" type="password" required 
                           class="w-full px-3 py-2 border rounded" 
                           placeholder="Пароль"
                           maxlength="50">
                </div>
                <div>
                    <button type="submit" 
                            class="w-full bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600">
                        Войти
                    </button>
                </div>
            </form>
        </div>
    </div>
    <script>
    document.querySelector('form').addEventListener('submit', function(e) {
        if (this.submitted) {
            e.preventDefault();
            return;
        }
        this.submitted = true;
        this.querySelector('button[type="submit"]').disabled = true;
    });
    </script>
</body>
</html>
<?php
    exit;
}


try {
    $mysqli = getDB();
    
    // Параметры пагинации
    $per_page = 50;
    $current_page = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;

    // Обработка смены пароля администратора
    if (isset($_POST['change_admin_password'])) {
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            throw new Exception('Недействительный токен безопасности');
        }

        $old_password = $_POST['old_password'] ?? '';
        $new_password = $_POST['new_password'] ?? '';
        $confirm_password = $_POST['confirm_password'] ?? '';

        if (empty($old_password) || empty($new_password) || empty($confirm_password)) {
            throw new Exception('Все поля должны быть заполнены');
        }

        if ($new_password !== $confirm_password) {
            throw new Exception('Новые пароли не совпадают');
        }

        if (strlen($new_password) < 8) {
            throw new Exception('Новый пароль должен быть не менее 8 символов');
        }

        $stmt = $mysqli->prepare("SELECT password_hash FROM admins WHERE id = ?");
        $stmt->bind_param("i", $_SESSION['admin_id']);
        $stmt->execute();
        $result = $stmt->get_result();
        $admin = $result->fetch_assoc();

        if (!password_verify($old_password, $admin['password_hash'])) {
            throw new Exception('Неверный текущий пароль');
        }

        $new_hash = password_hash($new_password, PASSWORD_DEFAULT);
        $stmt = $mysqli->prepare("UPDATE admins SET password_hash = ? WHERE id = ?");
        $stmt->bind_param("si", $new_hash, $_SESSION['admin_id']);
        
        if ($stmt->execute()) {
            $success_message = 'Пароль успешно изменен';
        } else {
            throw new Exception('Ошибка при изменении пароля');
        }
    }

    // Добавление одиночного пользователя
    if (isset($_POST['add_user'])) {
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            throw new Exception('Недействительный токен безопасности');
        }

        $email = filter_var($_POST['email'], FILTER_VALIDATE_EMAIL);
        $imap_password = sanitizeInput($_POST['imap_password']);
        $assoc_password = sanitizeInput($_POST['assoc_password']);

        if (!$email) {
            throw new Exception('Некорректный email');
        }

        if (strlen($imap_password) < 6 || strlen($assoc_password) < 6) {
            throw new Exception('Пароли должны быть не менее 6 символов');
        }

        $stmt = $mysqli->prepare("INSERT INTO users (email, imap_password, assoc_password) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $email, $imap_password, $assoc_password);
        
        if ($stmt->execute()) {
            $admin_id = $_SESSION['admin_id'];
            $log_stmt = $mysqli->prepare("INSERT INTO admin_logs (admin_id, action, ip_address, details) VALUES (?, 'add_user', ?, ?)");
            $ip = $_SERVER['REMOTE_ADDR'];
            $details = "Added user: $email";
            $log_stmt->bind_param("iss", $admin_id, $ip, $details);
            $log_stmt->execute();
            
            $success_message = 'Пользователь успешно добавлен';
        } else {
            throw new Exception('Ошибка при добавлении пользователя');
        }
    }

    // Пакетное добавление пользователей
    if (isset($_POST['bulk_add'])) {
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            throw new Exception('Недействительный токен безопасности');
        }

        $lines = explode("\n", $_POST['users']);
        $added = 0;
        $errors = [];
        
        $stmt = $mysqli->prepare("INSERT INTO users (email, imap_password, assoc_password) VALUES (?, ?, ?)");
        
        foreach ($lines as $line_num => $line) {
            $data = explode(":", trim($line));
            if (count($data) === 3 && filter_var($data[0], FILTER_VALIDATE_EMAIL)) {
                $stmt->bind_param("sss", $data[0], $data[1], $data[2]);
                if ($stmt->execute()) {
                    $added++;
                    // Логируем добавление
                    $admin_id = $_SESSION['admin_id'];
                    $log_stmt = $mysqli->prepare("INSERT INTO admin_logs (admin_id, action, ip_address, details) VALUES (?, 'add_user', ?, ?)");
                    $ip = $_SERVER['REMOTE_ADDR'];
                    $details = "Added user: {$data[0]}";
                    $log_stmt->bind_param("iss", $admin_id, $ip, $details);
                    $log_stmt->execute();
                } else {
                    $errors[] = "Строка {$line_num}: Ошибка добавления";
                }
            } else {
                $errors[] = "Строка {$line_num}: Неверный формат данных";
            }
        }
        
        if ($added > 0) {
            $success_message = "Добавлено пользователей: $added";
            if (!empty($errors)) {
                $success_message .= " (с ошибками: " . count($errors) . ")";
            }
        } else {
            throw new Exception("Не удалось добавить пользователей. " . implode(", ", $errors));
        }
    }


    // Инициализация переменных
    $total_users = 0;
    $stats = [
        'total_users' => 0,
        'active_users' => 0,
        'total_emails' => 0,
        'domain_stats' => [],
        'daily_stats' => []
    ];
    $users_result = null;
    $search_query = isset($_GET['search']) ? sanitizeInput($_GET['search']) : '';

    // Проверка существования необходимых таблиц
    $required_tables = [
        'email_domain_stats' => "
            CREATE TABLE IF NOT EXISTS `email_domain_stats` (
                `id` int(11) NOT NULL AUTO_INCREMENT,
                `domain` varchar(255) NOT NULL,
                `email_count` int(11) NOT NULL DEFAULT 0,
                PRIMARY KEY (`id`),
                UNIQUE KEY `domain` (`domain`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        ",
        'daily_stats' => "
            CREATE TABLE IF NOT EXISTS `daily_stats` (
                `id` int(11) NOT NULL AUTO_INCREMENT,
                `date` date NOT NULL,
                `total_emails` int(11) NOT NULL DEFAULT 0,
                `active_users` int(11) NOT NULL DEFAULT 0,
                PRIMARY KEY (`id`),
                UNIQUE KEY `date` (`date`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        ",
        'user_stats' => "
            CREATE TABLE IF NOT EXISTS `user_stats` (
                `id` int(11) NOT NULL AUTO_INCREMENT,
                `user_id` int(11) NOT NULL,
                `emails_downloaded` int(11) NOT NULL DEFAULT 0,
                `last_activity` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (`id`),
                UNIQUE KEY `user_id` (`user_id`),
                FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        "
    ];

    foreach ($required_tables as $table => $sql) {
        $mysqli->query($sql);
    }

    // Получение статистики
    $stats = getStats($mysqli);
    
    // Построение SQL запроса с учетом поиска
    $where_clause = "";
    $search_params = [];
    if (!empty($search_query)) {
        $where_clause = "WHERE email LIKE ?";
        $search_params[] = "%{$search_query}%";
    }

    // Получение общего количества пользователей
    try {
        if (empty($search_params)) {
            $result = $mysqli->query("SELECT COUNT(*) as count FROM users {$where_clause}");
        } else {
            $stmt = $mysqli->prepare("SELECT COUNT(*) as count FROM users {$where_clause}");
            $stmt->bind_param(str_repeat('s', count($search_params)), ...$search_params);
            $stmt->execute();
            $result = $stmt->get_result();
        }
        if ($result) {
            $total_users = (int)$result->fetch_assoc()['count'];
        }
    } catch (Exception $e) {
        error_log("Error getting total users: " . $e->getMessage());
    }

    // Настройка пагинации
    $pagination = getPagination($total_users, $per_page, $current_page);
    
    // Получение списка пользователей с пагинацией
    try {
        $query = "SELECT u.*, us.emails_downloaded, us.last_activity 
                 FROM users u 
                 LEFT JOIN user_stats us ON u.id = us.user_id 
                 {$where_clause} 
                 ORDER BY u.email 
                 LIMIT ? OFFSET ?";
                 
        $stmt = $mysqli->prepare($query);
        
        if (!empty($search_params)) {
            $types = str_repeat('s', count($search_params)) . 'ii';
            $params = array_merge($search_params, [$per_page, $pagination['offset']]);
            $stmt->bind_param($types, ...$params);
        } else {
            $stmt->bind_param("ii", $per_page, $pagination['offset']);
        }
        
        $stmt->execute();
        $users_result = $stmt->get_result();
        
    } catch (Exception $e) {
        error_log("Error getting users list: " . $e->getMessage());
        $users_result = null;
    }

    // Генерация нового CSRF токена
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

} catch (Exception $e) {
    $error = $e->getMessage();
    error_log("Admin error: " . $error);
}


?>
<!DOCTYPE html>
<html>
<head>
    <title>Админ-панель</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net/; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net/">
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2/dist/tailwind.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.7.0/dist/chart.min.js"></script>
</head>
<body class="bg-gray-100">
    <div class="min-h-screen">
        <!-- Верхняя панель -->
        <nav class="bg-white shadow-lg">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div class="flex justify-between h-16">
                    <div class="flex">
                        <div class="flex-shrink-0 flex items-center">
                            <h1 class="text-2xl font-bold text-gray-900">Админ-панель</h1>
                        </div>
                    </div>
                    <div class="flex items-center">
                        <span class="text-gray-600 mr-4">
                            Последний вход: 
                            <?php echo date('d.m.Y H:i', strtotime($_SESSION['admin_last_login'] ?? 'now')); ?>
                        </span>
                        <button id="showChangePasswordModal" 
                                class="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600 mr-2">
                            Сменить пароль
                        </button>
                        <a href="logout.php" 
                           class="bg-red-500 text-white px-4 py-2 rounded hover:bg-red-600">
                            Выход
                        </a>
                    </div>
                </div>
            </div>
        </nav>

        <!-- Основной контент -->
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            <?php if (isset($success_message)): ?>
                <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded mb-4" 
                     role="alert" id="success-message">
                    <?php echo htmlspecialchars($success_message); ?>
                </div>
            <?php endif; ?>

            <?php if (isset($error)): ?>
                <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4" 
                     role="alert">
                    <?php echo htmlspecialchars($error); ?>
                </div>
            <?php endif; ?>

            <!-- Блок статистики -->
            <div class="mb-8">
                <h2 class="text-xl font-bold mb-4">Статистика системы</h2>
                <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
                    <div class="bg-white p-6 rounded-lg shadow">
                        <div class="text-2xl font-bold">
                            <?php echo number_format($stats['total_users'] ?? 0); ?>
                        </div>
                        <div class="text-gray-600">Всего пользователей</div>
                    </div>
                    <div class="bg-white p-6 rounded-lg shadow">
                        <div class="text-2xl font-bold">
                            <?php echo number_format($stats['active_users'] ?? 0); ?>
                        </div>
                        <div class="text-gray-600">Активных пользователей</div>
                    </div>
                    <div class="bg-white p-6 rounded-lg shadow">
                        <div class="text-2xl font-bold">
                            <?php 
                            $active_percent = 0;
                            if (($stats['total_users'] ?? 0) > 0) {
                                $active_percent = round(($stats['active_users'] / $stats['total_users']) * 100, 1);
                            }
                            echo $active_percent . '%';
                            ?>
                        </div>
                        <div class="text-gray-600">Процент активности</div>
                    </div>
                    <div class="bg-white p-6 rounded-lg shadow">
                        <div class="text-2xl font-bold">
                             <?php echo number_format($stats['total_emails'] ?? 0); ?>
                        </div>
                        <div class="text-gray-600">Всего писем скачано</div>
                    </div>
                </div>
            </div>

            <!-- Графики -->
            <div class="grid grid-cols-1 md:grid-cols-2 gap-8 mb-8">
                <!-- График активности -->
                <div class="bg-white p-6 rounded-lg shadow">
                    <h3 class="text-lg font-bold mb-4">Активность за последние 30 дней</h3>
                    <canvas id="activityChart"></canvas>
                </div>

                <!-- График доменов -->
                <div class="bg-white p-6 rounded-lg shadow">
                    <h3 class="text-lg font-bold mb-4">Топ домены по количеству писем</h3>
                    <canvas id="domainChart"></canvas>
                </div>
            </div>


            <!-- Блок форм управления пользователями -->
            <div class="grid grid-cols-1 md:grid-cols-3 gap-8 mb-8">
                <!-- Добавление пользователя -->
                <div class="bg-white p-6 rounded-lg shadow">
                    <h2 class="text-xl font-bold mb-4">Добавить пользователя</h2>
                    <form method="POST" class="space-y-4" onsubmit="return validateForm(this)">
                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Email</label>
                            <input type="email" name="email" required 
                                   class="w-full px-3 py-2 border rounded" 
                                   placeholder="Email"
                                   pattern="[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">IMAP пароль</label>
                            <input type="text" name="imap_password" required 
                                   class="w-full px-3 py-2 border rounded" 
                                   placeholder="IMAP пароль"
                                   minlength="6">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Ассоциативный пароль</label>
                            <input type="text" name="assoc_password" required 
                                   class="w-full px-3 py-2 border rounded" 
                                   placeholder="Ассоциативный пароль"
                                   minlength="6">
                        </div>
                        <button type="submit" name="add_user" 
                                class="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600">
                            Добавить
                        </button>
                    </form>
                </div>

                <!-- Пакетное добавление -->
                <div class="bg-white p-6 rounded-lg shadow">
                    <h2 class="text-xl font-bold mb-4">Пакетное добавление</h2>
                    <form method="POST" class="space-y-4" onsubmit="return validateBulkForm(this)">
                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">
                                Формат: email:imap_password:assoc_password
                                <br>По одной записи на строку
                            </label>
                            <textarea name="users" rows="5" required
                                      class="w-full px-3 py-2 border rounded" 
                                      placeholder="email@domain.com:password1:password2"></textarea>
                        </div>
                        <button type="submit" name="bulk_add" 
                                class="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600">
                            Добавить пакетно
                        </button>
                    </form>
                </div>

                <!-- Поиск пользователей -->
                <div class="bg-white p-6 rounded-lg shadow">
                    <h2 class="text-xl font-bold mb-4">Поиск пользователей</h2>
                    <form method="GET" class="space-y-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Поиск по email</label>
                            <input type="text" name="search" 
                                   value="<?php echo htmlspecialchars($search_query); ?>"
                                   class="w-full px-3 py-2 border rounded" 
                                   placeholder="Введите email">
                        </div>
                        <div class="flex space-x-2">
                            <button type="submit" 
                                    class="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600">
                                Поиск
                            </button>
                            <?php if (!empty($search_query)): ?>
                                <a href="?" class="bg-gray-500 text-white px-4 py-2 rounded hover:bg-gray-600">
                                    Сбросить
                                </a>
                            <?php endif; ?>
                        </div>
                    </form>
                </div>
            </div>


            <!-- Таблица пользователей -->
            <div class="bg-white rounded-lg shadow">
                <div class="px-6 py-4 border-b border-gray-200">
                    <h2 class="text-xl font-bold">
                        Пользователи 
                        (<?php echo number_format(($pagination['offset'] ?? 0) + 1); ?> - 
                        <?php echo number_format(min(($pagination['offset'] ?? 0) + $pagination['per_page'], $total_users)); ?> 
                        из <?php echo number_format($total_users); ?>)
                        <?php if (!empty($search_query)): ?>
                            <span class="text-sm font-normal ml-2">
                                Поиск: "<?php echo htmlspecialchars($search_query); ?>"
                            </span>
                        <?php endif; ?>
                    </h2>
                </div>

                <div class="overflow-x-auto">
                    <table class="min-w-full divide-y divide-gray-200">
                        <thead>
                            <tr>
                                <th class="px-6 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Email</th>
                                <th class="px-6 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">IMAP пароль</th>
                                <th class="px-6 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Ассоц. пароль</th>
                                <th class="px-6 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Писем скачано</th>
                                <th class="px-6 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Последняя активность</th>
                                <th class="px-6 py-3 bg-gray-50 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Действия</th>
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-200">
                            <?php if ($users_result && $users_result->num_rows > 0): ?>
                                <?php while ($user = $users_result->fetch_assoc()): ?>
                                    <tr>
                                        <td class="px-6 py-4 whitespace-nowrap">
                                            <?php echo htmlspecialchars($user['email']); ?>
                                        </td>
                                        <td class="px-6 py-4 whitespace-nowrap">
                                            <span class="password-hidden">
                                                <?php echo htmlspecialchars($user['imap_password']); ?>
                                            </span>
                                        </td>
                                        <td class="px-6 py-4 whitespace-nowrap">
                                            <span class="password-hidden">
                                                <?php echo htmlspecialchars($user['assoc_password']); ?>
                                            </span>
                                        </td>
                                        <td class="px-6 py-4 whitespace-nowrap">
                                            <?php echo number_format($user['emails_downloaded'] ?? 0); ?>
                                        </td>
                                        <td class="px-6 py-4 whitespace-nowrap">
                                            <?php 
                                            if (!empty($user['last_activity'])) {
                                                echo date('d.m.Y H:i', strtotime($user['last_activity']));
                                            } else {
                                                echo '<span class="text-gray-500">Не активен</span>';
                                            }
                                            ?>
                                        </td>
                                        <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                            <button onclick="editUser(<?php echo htmlspecialchars(json_encode($user), ENT_QUOTES, 'UTF-8'); ?>)"
                                                    class="text-blue-600 hover:text-blue-900 mx-2">
                                                Редактировать
                                            </button>
                                            <form method="POST" class="inline" onsubmit="return confirm('Удалить этого пользователя?');">
                                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                                <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                                                <button type="submit" name="delete_user" 
                                                        class="text-red-600 hover:text-red-900">
                                                    Удалить
                                                </button>
                                            </form>
                                        </td>
                                    </tr>
                                <?php endwhile; ?>
                            <?php else: ?>
                                <tr>
                                    <td colspan="6" class="px-6 py-4 text-center text-gray-500">
                                        <?php echo empty($search_query) ? 'Нет пользователей' : 'Ничего не найдено'; ?>
                                    </td>
                                </tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>

                <!-- Пагинация -->
                <?php if ($pagination['total_pages'] > 1): ?>
                    <div class="px-6 py-4 bg-gray-50 border-t border-gray-200">
                        <div class="flex justify-center space-x-2">
                            <?php 
                            $url_params = [];
                            if (!empty($search_query)) {
                                $url_params['search'] = $search_query;
                            }
                            
                            if ($pagination['current_page'] > 1):
                                $url_params['page'] = 1;
                            ?>
                                <a href="?<?php echo http_build_query($url_params); ?>" 
                                   class="px-3 py-1 bg-gray-200 rounded hover:bg-gray-300">«</a>
                                <?php 
                                $url_params['page'] = $pagination['current_page'] - 1;
                                ?>
                                <a href="?<?php echo http_build_query($url_params); ?>" 
                                   class="px-3 py-1 bg-gray-200 rounded hover:bg-gray-300">‹</a>
                            <?php endif; ?>

                            <?php
                            $start = max(1, $pagination['current_page'] - 2);
                            $end = min($pagination['total_pages'], $pagination['current_page'] + 2);
                            
                            for ($i = $start; $i <= $end; $i++):
                                $url_params['page'] = $i;
                            ?>
                                <a href="?<?php echo http_build_query($url_params); ?>" 
                                   class="px-3 py-1 rounded <?php echo $i === $pagination['current_page'] ? 'bg-blue-500 text-white' : 'bg-gray-200 hover:bg-gray-300'; ?>">
                                    <?php echo $i; ?>
                                </a>
                            <?php endfor; ?>

                            <?php if ($pagination['current_page'] < $pagination['total_pages']): ?>
                                <?php 
                                $url_params['page'] = $pagination['current_page'] + 1;
                                ?>
                                <a href="?<?php echo http_build_query($url_params); ?>" 
                                   class="px-3 py-1 bg-gray-200 rounded hover:bg-gray-300">›</a>
                                <?php 
                                $url_params['page'] = $pagination['total_pages'];
                                ?>
                                <a href="?<?php echo http_build_query($url_params); ?>" 
                                   class="px-3 py-1 bg-gray-200 rounded hover:bg-gray-300">»</a>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>


    <!-- Модальное окно смены пароля администратора -->
    <div id="changePasswordModal" class="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full hidden">
        <div class="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
            <div class="mt-3">
                <h3 class="text-lg font-medium leading-6 text-gray-900 mb-4">Смена пароля администратора</h3>
                <form method="POST" class="space-y-4">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Текущий пароль</label>
                        <input type="password" name="old_password" required 
                               class="mt-1 block w-full border rounded-md shadow-sm py-2 px-3"
                               minlength="8">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Новый пароль</label>
                        <input type="password" name="new_password" required 
                               class="mt-1 block w-full border rounded-md shadow-sm py-2 px-3"
                               minlength="8">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Подтверждение пароля</label>
                        <input type="password" name="confirm_password" required 
                               class="mt-1 block w-full border rounded-md shadow-sm py-2 px-3"
                               minlength="8">
                    </div>
                    <div class="flex justify-end space-x-2">
                        <button type="button" onclick="closeModal('changePasswordModal')" 
                                class="bg-gray-500 text-white px-4 py-2 rounded hover:bg-gray-600">
                            Отмена
                        </button>
                        <button type="submit" name="change_admin_password" 
                                class="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600">
                            Сохранить
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Модальное окно для редактирования пользователя -->
    <div id="editModal" class="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full hidden">
        <div class="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
            <div class="mt-3">
                <h3 class="text-lg leading-6 font-medium text-gray-900 mb-4">Редактировать пользователя</h3>
                <form method="POST" class="space-y-4" id="editForm">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                    <input type="hidden" name="user_id" id="edit_user_id">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Email</label>
                        <input type="email" name="email" id="edit_email" required 
                               class="w-full px-3 py-2 border rounded">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">IMAP пароль</label>
                        <input type="text" name="imap_password" id="edit_imap_password" required 
                               class="w-full px-3 py-2 border rounded">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Ассоциативный пароль</label>
                        <input type="text" name="assoc_password" id="edit_assoc_password" required 
                               class="w-full px-3 py-2 border rounded">
                    </div>
                    <div class="flex justify-end space-x-2 mt-4">
                        <button type="button" onclick="closeModal('editModal')" 
                                class="bg-gray-500 text-white px-4 py-2 rounded hover:bg-gray-600">
                            Отмена
                        </button>
                        <button type="submit" name="edit_user" 
                                class="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600">
                            Сохранить
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script>
    // Инициализация графиков
    const activityChart = new Chart(document.getElementById('activityChart').getContext('2d'), {
        type: 'line',
        data: {
            labels: <?php echo json_encode(array_column($stats['daily_stats'], 'date')); ?>,
            datasets: [{
                label: 'Скачано писем',
                data: <?php echo json_encode(array_column($stats['daily_stats'], 'total_emails')); ?>,
                borderColor: 'rgb(59, 130, 246)',
                tension: 0.1
            }, {
                label: 'Активные пользователи',
                data: <?php echo json_encode(array_column($stats['daily_stats'], 'active_users')); ?>,
                borderColor: 'rgb(16, 185, 129)',
                tension: 0.1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });

    const domainChart = new Chart(document.getElementById('domainChart').getContext('2d'), {
        type: 'bar',
        data: {
            labels: <?php echo json_encode(array_column($stats['domain_stats'], 'domain')); ?>,
            datasets: [{
                label: 'Количество писем',
                data: <?php echo json_encode(array_column($stats['domain_stats'], 'email_count')); ?>,
                backgroundColor: 'rgba(59, 130, 246, 0.5)',
                borderColor: 'rgb(59, 130, 246)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });

    // Функции для модальных окон
    function openModal(modalId) {
        document.getElementById(modalId).classList.remove('hidden');
        document.body.style.overflow = 'hidden';
    }

    function closeModal(modalId) {
        document.getElementById(modalId).classList.add('hidden');
        document.body.style.overflow = 'auto';
    }

    // Функции для управления пользователями
    function editUser(user) {
        document.getElementById('edit_user_id').value = user.id;
        document.getElementById('edit_email').value = decodeHTMLEntities(user.email);
        document.getElementById('edit_imap_password').value = decodeHTMLEntities(user.imap_password);
        document.getElementById('edit_assoc_password').value = decodeHTMLEntities(user.assoc_password);
        openModal('editModal');
    }

    function decodeHTMLEntities(text) {
        const textarea = document.createElement('textarea');
        textarea.innerHTML = text;
        return textarea.value;
    }

    // Функции валидации форм
    function validateForm(form) {
        const email = form.email.value;
        const imapPass = form.imap_password.value;
        const assocPass = form.assoc_password.value;

        if (!email.match(/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/)) {
            alert('Пожалуйста, введите корректный email');
            return false;
        }

        if (imapPass.length < 6 || assocPass.length < 6) {
            alert('Пароли должны быть не менее 6 символов');
            return false;
        }

        return true;
    }

    function validateBulkForm(form) {
        const lines = form.users.value.trim().split('\n');
        let isValid = true;
        let errors = [];

        lines.forEach((line, index) => {
            const parts = line.trim().split(':');
            if (parts.length !== 3) {
                errors.push(`Строка ${index + 1}: неверный формат`);
                isValid = false;
                return;
            }

            const [email, imapPass, assocPass] = parts;
            if (!email.match(/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/)) {
                errors.push(`Строка ${index + 1}: некорректный email`);
                isValid = false;
            }

            if (imapPass.length < 6 || assocPass.length < 6) {
                errors.push(`Строка ${index + 1}: пароли должны быть не менее 6 символов`);
                isValid = false;
            }
        });

        if (!isValid) {
            alert('Ошибки в данных:\n' + errors.join('\n'));
        }

        return isValid;
    }

    // Обработчики событий
    document.getElementById('showChangePasswordModal').addEventListener('click', function() {
        openModal('changePasswordModal');
    });

    // Закрытие модальных окон при клике вне их
    window.onclick = function(event) {
        if (event.target.classList.contains('fixed')) {
            closeModal(event.target.id);
        }
    }

    // Предотвращение случайного закрытия страницы
    let formChanged = false;
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('change', () => {
            formChanged = true;
        });
        form.addEventListener('submit', () => {
            formChanged = false;
        });
    });

    window.addEventListener('beforeunload', function(e) {
        if (formChanged) {
            e.preventDefault();
            e.returnValue = '';
        }
    });

    // Автоматическое скрытие сообщений об успехе
    const successMessage = document.getElementById('success-message');
    if (successMessage) {
        setTimeout(() => {
            successMessage.style.opacity = '0';
            setTimeout(() => successMessage.remove(), 500);
        }, 3000);
    }
    </script>
</body>
</html>
