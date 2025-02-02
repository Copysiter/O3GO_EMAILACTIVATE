<?php
session_start();
require_once 'config.php';

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

// Получение статистики
function getStats() {
    try {
        $mysqli = getDB();
        $stats = [
            'total_users' => 0,
            'total_emails' => 0,
            'active_today' => 0
        ];
        
        // Общее количество пользователей
        $result = $mysqli->query("SELECT COUNT(*) as count FROM users");
        if ($result) {
            $stats['total_users'] = $result->fetch_assoc()['count'];
        }
        
        // Общее количество писем
        $result = $mysqli->query("SELECT SUM(emails_downloaded) as total FROM user_stats");
        if ($result) {
            $stats['total_emails'] = (int)$result->fetch_assoc()['total'];
        }
        
        // Активные пользователи сегодня
        $result = $mysqli->query("SELECT COUNT(DISTINCT user_id) as count FROM user_stats WHERE DATE(last_activity) = CURDATE()");
        if ($result) {
            $stats['active_today'] = $result->fetch_assoc()['count'];
        }
        
        return $stats;
    } catch (Exception $e) {
        error_log($e->getMessage());
        return ['total_users' => 0, 'total_emails' => 0, 'active_today' => 0];
    }
}

$error = '';
$stats = getStats();

// Проверка авторизации админа или пользователя
if (isset($_POST['username']) && isset($_POST['password'])) {
    try {
        checkLoginAttempts();
        
        $username = filter_var($_POST['username'], FILTER_SANITIZE_EMAIL);
        $password = $_POST['password'];
        
        if (empty($username) || empty($password)) {
            throw new Exception("Заполните все поля");
        }
        
        $mysqli = getDB();
        
        // Сначала проверяем, не админ ли это
        $stmt = $mysqli->prepare("SELECT id, password_hash, last_login FROM admins WHERE username = ? LIMIT 1");
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
        
        // Если не админ, проверяем обычного пользователя
        $stmt = $mysqli->prepare("SELECT id, assoc_password FROM users WHERE email = ? LIMIT 1");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($user = $result->fetch_assoc()) {
            if ($password === $user['assoc_password']) {
                $_SESSION['user_id'] = $user['id'];
                header('Location: mail.php');
                exit;
            }
        }
        
        $_SESSION['login_attempts']++;
        throw new Exception("Неверные учетные данные");
        
    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

// Генерация CSRF токена
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <title>Email Service - Доступ к почтовым ящикам</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net/; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net/">
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2/dist/tailwind.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body class="bg-gray-50">
    <!-- Header -->
    <header class="bg-white shadow">
        <nav class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex justify-between h-16">
                <div class="flex items-center">
                    <span class="text-2xl font-bold text-blue-600">
                        <i class="fas fa-envelope-open-text mr-2"></i>
                        Email Service
                    </span>
                </div>
                <div class="flex items-center">
                    <a href="#prices" class="text-gray-700 hover:text-blue-600 px-3 py-2">Цены</a>
                    <a href="#stats" class="text-gray-700 hover:text-blue-600 px-3 py-2">Статистика</a>
                    <a href="#login" class="ml-4 bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700">
                        Войти
                    </a>
                </div>
            </div>
        </nav>
    </header>

    <!-- Hero Section -->
    <div class="relative bg-white overflow-hidden">
        <div class="max-w-7xl mx-auto">
            <div class="relative z-10 pb-8 bg-white sm:pb-16 md:pb-20 lg:pb-28 xl:pb-32">
                <main class="mt-10 mx-auto max-w-7xl px-4 sm:mt-12 sm:px-6 md:mt-16 lg:mt-20 lg:px-8 xl:mt-28">
                    <div class="text-center">
                        <h1 class="text-4xl tracking-tight font-extrabold text-gray-900 sm:text-5xl md:text-6xl">
                            <span class="block">Доступ к почтовым ящикам</span>
                            <span class="block text-blue-600">быстро и надежно</span>
                        </h1>
                        <p class="mt-3 text-base text-gray-500 sm:mt-5 sm:text-lg sm:max-w-xl sm:mx-auto md:mt-5 md:text-xl">
                            Получите доступ к вашим почтовым ящикам по выгодным ценам. 
                            Используйте разовый доступ или безлимитную подписку.
                        </p>
                    </div>
                </main>
            </div>
        </div>
    </div>
    <!-- Prices Section -->
    <div id="prices" class="py-12 bg-gray-50">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="text-center">
                <h2 class="text-3xl font-extrabold text-gray-900">Тарифы</h2>
            </div>
            <div class="mt-10">
                <div class="grid grid-cols-1 gap-8 sm:grid-cols-2 lg:grid-cols-2">
                    <!-- Разовый доступ -->
                    <div class="bg-white rounded-lg shadow-lg overflow-hidden">
                        <div class="px-6 py-8">
                            <div class="flex items-center justify-center">
                                <i class="fas fa-envelope text-5xl text-blue-500 mb-4"></i>
                            </div>
                            <h3 class="text-center text-2xl font-medium text-gray-900">Разовый доступ</h3>
                            <div class="mt-4 flex justify-center">
                                <span class="px-3 py-1 text-xl font-semibold text-green-500">30 копеек</span>
                                <span class="text-gray-500 self-end">/письмо</span>
                            </div>
                            <ul class="mt-6 space-y-4">
                                <li class="flex items-center">
                                    <i class="fas fa-check text-green-500 mr-2"></i>
                                    Мгновенный доступ
                                </li>
                                <li class="flex items-center">
                                    <i class="fas fa-check text-green-500 mr-2"></i>
                                    Оплата за результат
                                </li>
                                <li class="flex items-center">
                                    <i class="fas fa-check text-green-500 mr-2"></i>
                                    Без обязательств
                                </li>
                            </ul>
                        </div>
                    </div>

                    <!-- Безлимитный доступ -->
                    <div class="bg-white rounded-lg shadow-lg overflow-hidden border-2 border-blue-500">
                        <div class="px-6 py-8">
                            <div class="flex items-center justify-center">
                                <i class="fas fa-infinity text-5xl text-blue-500 mb-4"></i>
                            </div>
                            <h3 class="text-center text-2xl font-medium text-gray-900">Безлимитный доступ</h3>
                            <div class="mt-4 flex justify-center">
                                <span class="px-3 py-1 text-xl font-semibold text-green-500">1 рубль</span>
                                <span class="text-gray-500 self-end">/почта</span>
                            </div>
                            <ul class="mt-6 space-y-4">
                                <li class="flex items-center">
                                    <i class="fas fa-check text-green-500 mr-2"></i>
                                    Неограниченное количество писем
                                </li>
                                <li class="flex items-center">
                                    <i class="fas fa-check text-green-500 mr-2"></i>
                                    Приоритетная поддержка
                                </li>
                                <li class="flex items-center">
                                    <i class="fas fa-check text-green-500 mr-2"></i>
                                    Постоянный доступ
                                </li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <!-- Stats Section -->
    <div id="stats" class="py-12 bg-white">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="text-center">
                <h2 class="text-3xl font-extrabold text-gray-900">Наша статистика</h2>
            </div>
            <div class="mt-10">
                <div class="grid grid-cols-1 gap-8 sm:grid-cols-3">
                    <div class="bg-blue-50 rounded-lg p-6 text-center">
                        <div class="text-4xl font-bold text-blue-600">
                            <?php echo number_format($stats['total_users']); ?>+
                        </div>
                        <div class="mt-2 text-gray-600">Активных пользователей</div>
                    </div>
                    <div class="bg-blue-50 rounded-lg p-6 text-center">
                        <div class="text-4xl font-bold text-blue-600">
                            <?php echo number_format($stats['total_emails']); ?>+
                        </div>
                        <div class="mt-2 text-gray-600">Обработано писем</div>
                    </div>
                    <div class="bg-blue-50 rounded-lg p-6 text-center">
                        <div class="text-4xl font-bold text-blue-600">
                            <?php echo number_format($stats['active_today']); ?>
                        </div>
                        <div class="mt-2 text-gray-600">Активны сегодня</div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Login Form -->
    <div id="login" class="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
        <div class="max-w-md w-full space-y-8">
            <div>
                <h2 class="mt-6 text-center text-3xl font-extrabold text-gray-900">
                    Вход в систему
                </h2>
                <p class="mt-2 text-center text-sm text-gray-600">
                    Войдите в свой аккаунт для доступа к почте
                </p>
            </div>
            <?php if (isset($error)): ?>
                <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative">
                    <?php echo htmlspecialchars($error); ?>
                </div>
            <?php endif; ?>
            <form class="mt-8 space-y-6" method="POST" onsubmit="return validateForm(this)">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <div class="rounded-md shadow-sm -space-y-px">
                    <div>
                        <label for="username" class="sr-only">Email или логин</label>
                        <input id="username" name="username" type="text" required 
                               class="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-t-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 focus:z-10 sm:text-sm" 
                               placeholder="Email или логин"
                               pattern="[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|[a-zA-Z0-9]+"
                               title="Введите email или логин"
                               maxlength="50">
                    </div>
                    <div>
                        <label for="password" class="sr-only">Пароль</label>
                        <input id="password" name="password" type="password" required 
                               class="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-b-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 focus:z-10 sm:text-sm" 
                               placeholder="Пароль"
                               maxlength="50">
                    </div>
                </div>

                <div>
                    <button type="submit" class="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
                        <span class="absolute left-0 inset-y-0 flex items-center pl-3">
                            <i class="fas fa-sign-in-alt"></i>
                        </span>
                        Войти
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- Footer -->
    <footer class="bg-white border-t">
        <div class="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
            <div class="text-center text-gray-500">
                &copy; <?php echo date('Y'); ?> Email Service. Все права защищены.
            </div>
        </div>
    </footer>

    <script>
    // Валидация формы
    function validateForm(form) {
        if (form.submitted) {
            return false;
        }
        form.submitted = true;
        form.querySelector('button[type="submit"]').disabled = true;
        return true;
    }

    // Автоматическое скрытие сообщений об ошибках
    document.addEventListener('DOMContentLoaded', function() {
        const errorMessage = document.querySelector('.bg-red-100');
        if (errorMessage) {
            setTimeout(() => {
                errorMessage.style.opacity = '0';
                errorMessage.style.transition = 'opacity 0.5s';
                setTimeout(() => errorMessage.remove(), 500);
            }, 5000);
        }
    });

    // Плавная прокрутка к секциям
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const element = document.querySelector(this.getAttribute('href'));
            if (element) {
                element.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    // Анимация чисел в статистике
    function animateValue(element, start, end, duration) {
        let startTimestamp = null;
        const step = (timestamp) => {
            if (!startTimestamp) startTimestamp = timestamp;
            const progress = Math.min((timestamp - startTimestamp) / duration, 1);
            const current = Math.floor(progress * (end - start) + start);
            element.textContent = current.toLocaleString() + '+';
            if (progress < 1) {
                window.requestAnimationFrame(step);
            }
        };
        window.requestAnimationFrame(step);
    }

    // Запуск анимации при прокрутке до секции статистики
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const statsElements = entry.target.querySelectorAll('.text-4xl');
                statsElements.forEach(el => {
                    const value = parseInt(el.textContent.replace(/[^0-9]/g, ''));
                    animateValue(el, 0, value, 2000);
                });
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.5 });

    const statsSection = document.querySelector('#stats');
    if (statsSection) {
        observer.observe(statsSection);
    }
    </script>
</body>
</html>