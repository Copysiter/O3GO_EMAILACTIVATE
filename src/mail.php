<?php
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.use_strict_mode', 1);

session_start();
require_once 'config.php';
require_once 'functions.php';

// Функция для маркировки письма как прочитанного
function markEmailAsRead($imap, $msgNum) {
    if (!is_numeric($msgNum)) {
        return false;
    }
    return imap_setflag_full($imap, $msgNum, "\\Seen");
}

// Функция форматирования email адреса
function formatEmailAddress($email, $name = '') {
    $email = trim($email);
    $name = trim($name);
    if (empty($name) || $name === $email) {
        return $email;
    }
    return $name . ' <' . $email . '>';
}

// Функция проверки адреса email
function isEmailMatch($email1, $email2) {
    return strtolower(trim($email1)) === strtolower(trim($email2));
}

// Функция для определения типа контента письма
function isHTMLContent($structure) {
    if ($structure->subtype === 'HTML' || $structure->subtype === 'ALTERNATIVE') {
        return true;
    }
    return false;
}

// Функция для безопасной обработки контента писем
function sanitizeContent($content, $isHTML) {
    if (!$isHTML) {
        return nl2br(htmlspecialchars($content, ENT_QUOTES, 'UTF-8'));
    }

    // Если это HTML - обрабатываем
    $encoding = mb_detect_encoding($content, ['UTF-8', 'Windows-1251', 'KOI8-R'], true);
    if ($encoding && $encoding !== 'UTF-8') {
        $content = mb_convert_encoding($content, 'UTF-8', $encoding);
    }

    // Удаляем потенциально опасные теги
    $content = preg_replace('/<script\b[^>]*>(.*?)<\/script>/is', '', $content);
    
    return $content;
}

// Проверка авторизации
if (!isset($_SESSION['user'], $_SESSION['imap_password'])) {
    header('Location: index.php');
    exit;
}

// Обновление идентификатора сессии
session_regenerate_id(true);

// Защита от XSS
$email = htmlspecialchars($_SESSION['user'], ENT_QUOTES, 'UTF-8');
$imap_password = $_SESSION['imap_password'];
$error = null;
try {
    // Проверка входных параметров
    if (isset($_GET['folder'])) {
        if (preg_match('/[\'"<>]/', $_GET['folder'])) {
            throw new Exception('Недопустимые символы в имени папки');
        }
    }

    // IMAP подключение
    $imap = @imap_open("{imap.yandex.ru:993/imap/ssl}INBOX", $email, $imap_password);
    if (!$imap) {
        throw new Exception('Ошибка подключения к IMAP: ' . imap_last_error());
    }

    // Получение списка папок
    $folders = imap_list($imap, "{imap.yandex.ru:993/imap/ssl}", "*");
    $folders = array_map(function($folder) {
        $name = str_replace("{imap.yandex.ru:993/imap/ssl}", "", $folder);
        $label = str_replace(
            ['}Sent', '}Drafts', '}Trash', '}Spam', '}INBOX'], 
            ['Отправленные', 'Черновики', 'Корзина', 'Спам', 'Входящие'], 
            basename($name)
        );
        return [
            'name' => $name,
            'label' => $label
        ];
    }, $folders ?: []);

    // Обработка текущей папки
    $currentFolder = $_GET['folder'] ?? 'INBOX';
    if ($currentFolder !== 'INBOX') {
        if (strpos(strtolower($currentFolder), 'spam') !== false) {
            imap_close($imap);
            $imap = @imap_open("{imap.yandex.ru:993/imap/ssl}Spam", $email, $imap_password);
            $currentFolder = "Spam";
        } else {
            $validFolders = array_column($folders, 'name');
            if (!in_array($currentFolder, $validFolders)) {
                throw new Exception('Недопустимая папка');
            }
            imap_reopen($imap, "{imap.yandex.ru:993/imap/ssl}" . $currentFolder);
        }
    }

// Поиск писем с точным соответствием адреса
    $messages = [];
    $cleanEmail = str_replace(['"', "'", '\\'], '', $email);
    
    // Используем одинаковый поиск для всех папок
    $emails = imap_search($imap, 'ALL');
    
    if ($emails) {
        rsort($emails);
        foreach ($emails as $msgNum) {
            if (!is_numeric($msgNum)) continue;

            $header = imap_headerinfo($imap, $msgNum);
            $structure = imap_fetchstructure($imap, $msgNum);
            
            // Проверяем, действительно ли письмо предназначено этому пользователю
            $isForUser = false;
            if (isset($header->to)) {
                foreach ($header->to as $recipient) {
                    if (isset($recipient->mailbox) && isset($recipient->host)) {
                        $recipientEmail = $recipient->mailbox . '@' . $recipient->host;
                        // Точное сравнение email адресов
                        if ($recipientEmail === $cleanEmail) {
                            $isForUser = true;
                            break;
                        }
                    }
                }
            }

            // Если письмо не для этого пользователя - пропускаем
            if (!$isForUser) {
                continue;
            }
            
            // Получение данных отправителя
            $fromName = '';
            $fromEmail = '';
            if (isset($header->from[0])) {
                $from = $header->from[0];
                $fromName = isset($from->personal) ? decodeMimeStr($from->personal) : '';
                $fromEmail = $from->mailbox . '@' . $from->host;
            }
            
            // Получение списка получателей
            $to = [];
            if (isset($header->to)) {
                foreach ($header->to as $recipient) {
                    if (isset($recipient->mailbox) && isset($recipient->host)) {
                        $recipientEmail = $recipient->mailbox . '@' . $recipient->host;
                        if (isEmailMatch($recipientEmail, $cleanEmail)) {
                            $recipientName = isset($recipient->personal) ? decodeMimeStr($recipient->personal) : '';
                            $to[] = formatEmailAddress($recipientEmail, $recipientName);
                        }
                    }
                }
            }
            
            // Получение тела письма
            $body = null;
            if (isset($_GET['show']) && $_GET['show'] == $msgNum && is_numeric($_GET['show'])) {
                markEmailAsRead($imap, $msgNum);
                $isHTML = isHTMLContent($structure);
                $rawBody = getMessageBody($imap, $msgNum, $structure);
                if ($rawBody) {
                    $body = sanitizeContent($rawBody, $isHTML);
                }
            }

            // Форматирование даты
            $date = date('d.m.Y H:i', strtotime($header->date));
            if ($date === false) {
                $date = 'Дата неизвестна';
            }

            // Добавление сообщения в массив
            $messages[] = [
                'num' => (int)$msgNum,
                'subject' => decodeMimeStr($header->subject ?? '(Без темы)'),
                'from' => formatEmailAddress($fromEmail, $fromName),
                'to' => implode(', ', $to),
                'date' => $date,
                'hasAttachments' => hasAttachments($structure),
                'unread' => !isset($header->Seen),
                'body' => $body,
                'isHTML' => isset($isHTML) ? $isHTML : false
            ];
        }
    }

    imap_close($imap);
} catch (Exception $e) {
    $error = $e->getMessage();
    error_log("Email error for user $email: " . $e->getMessage());
}
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net/; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net/">
    <meta http-equiv="X-Frame-Options" content="DENY">
    <meta http-equiv="X-XSS-Protection" content="1; mode=block">
    <meta http-equiv="X-Content-Type-Options" content="nosniff">
    <title>Почта - <?php echo htmlspecialchars($email, ENT_QUOTES, 'UTF-8'); ?></title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2/dist/tailwind.min.css" rel="stylesheet">
    <style>
        .email-content {
            width: 100%;
            padding: 15px;
            background: white;
            border-radius: 4px;
            margin-top: 10px;
        }
        .email-content img {
            max-width: 100%;
            height: auto;
        }
        .email-content a {
            color: #2563eb;
            text-decoration: underline;
        }
        .email-content blockquote {
            margin: 10px 0;
            padding-left: 15px;
            border-left: 3px solid #e5e7eb;
            color: #666;
        }
        .email-address {
            white-space: normal;
            word-break: break-word;
        }
        .email-header {
            margin-bottom: 5px;
            line-height: 1.4;
        }
        .email-content.plain-text {
            font-family: monospace;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .email-wrapper {
            width: 100%;
            max-width: 100%;
            overflow-x: auto;
        }
        .email-content table {
            max-width: 100%;
            border-collapse: separate;
            border-spacing: 2px;
            margin: 10px 0;
        }
        .email-content td, 
        .email-content th {
            padding: 8px;
            border: 1px solid #e5e7eb;
        }
        /* Сохраняем оригинальные стили email клиентов */
        .email-content .ExternalClass {
            width: 100%;
        }
        .email-content .ExternalClass,
        .email-content .ExternalClass p,
        .email-content .ExternalClass span,
        .email-content .ExternalClass font,
        .email-content .ExternalClass td,
        .email-content .ExternalClass div {
            line-height: 100%;
        }
    </style>
</head>
<body class="bg-gray-100">
    <nav class="bg-gray-800 text-white">
        <div class="max-w-7xl mx-auto px-4 py-3">
            <div class="flex justify-between items-center">
                <h1 class="text-xl"><?php echo htmlspecialchars($email, ENT_QUOTES, 'UTF-8'); ?></h1>
                <div class="flex gap-2">
                    <a href="?folder=<?php echo urlencode($currentFolder); ?>" 
                       class="px-3 py-1 bg-blue-500 rounded hover:bg-blue-600">Обновить</a>
                    <a href="logout.php" class="px-3 py-1 bg-red-500 rounded hover:bg-red-600">Выход</a>
                </div>
            </div>
        </div>
    </nav>

    <?php if ($error): ?>
        <div class="max-w-7xl mx-auto p-4">
            <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
                <?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?>
            </div>
        </div>
    <?php endif; ?>

    <main class="max-w-7xl mx-auto p-4">
        <div class="flex gap-4">
            <!-- Левая колонка с папками -->
            <div class="w-64 bg-white rounded p-4">
                <h2 class="font-bold mb-3">Папки</h2>
                <div class="space-y-1">
                    <?php foreach ($folders as $folder): ?>
                        <a href="?folder=<?php echo urlencode($folder['name']); ?>"
                           class="flex items-center p-2 rounded hover:bg-gray-100 
                                  <?php echo $currentFolder === $folder['name'] ? 'bg-gray-100' : ''; ?>">
                            <?php 
                            $icon = match($folder['label']) {
                                'Входящие' => '📥',
                                'Отправленные' => '📤',
                                'Черновики' => '📝',
                                'Корзина' => '🗑️',
                                'Спам' => '⚠️',
                                default => '📁'
                            };
                            echo $icon . ' ' . htmlspecialchars($folder['label'], ENT_QUOTES, 'UTF-8'); 
                            ?>
                        </a>
                    <?php endforeach; ?>
                </div>
            </div>

            <!-- Правая колонка с письмами -->
            <div class="flex-1 bg-white rounded p-4">
                <?php if (empty($messages)): ?>
                    <div class="text-center text-gray-500 py-8">
                        Нет писем
                    </div>
                <?php else: ?>
                    <div class="space-y-4">
					<?php foreach ($messages as $message): ?>
                            <div class="border rounded p-4 <?php echo $message['unread'] ? 'bg-blue-50' : ''; ?>">
                                <div class="block hover:bg-gray-50">
                                    <div class="flex justify-between">
                                        <div class="flex-1">
                                            <div class="email-header text-lg <?php echo $message['unread'] ? 'font-bold' : ''; ?>">
                                                <?php echo htmlspecialchars($message['subject']); ?>
                                            </div>
                                            <div class="email-header text-sm text-gray-600">
                                                <span class="font-medium">От:</span> 
                                                <?php echo htmlspecialchars($message['from']); ?>
                                            </div>
                                            <div class="email-header text-sm text-gray-600 email-address">
                                                <span class="font-medium">Кому:</span> 
                                                <?php 
                                                // Показываем только адрес текущего пользователя
                                                echo htmlspecialchars($email);
                                                ?>
                                            </div>
                                            <div class="email-header text-sm text-gray-500">
                                                <?php echo htmlspecialchars($message['date']); ?>
                                            </div>
                                        </div>
                                        <div class="flex gap-2 ml-4">
                                            <?php if ($message['hasAttachments']): ?>
                                                <span class="px-2 py-1 bg-blue-100 text-xs rounded-full">
                                                    Вложения
                                                </span>
                                            <?php endif; ?>
                                            <?php if ($message['unread']): ?>
                                                <span class="px-2 py-1 bg-green-100 text-xs rounded-full">
                                                    Новое
                                                </span>
                                            <?php endif; ?>
                                        </div>
                                    </div>
									<?php if (!isset($_GET['show']) || $_GET['show'] != $message['num']): ?>
                                        <div class="mt-2">
                                            <a href="?folder=<?php echo urlencode($currentFolder); ?>&show=<?php echo $message['num']; ?>"
                                               class="text-blue-500 hover:text-blue-600">
                                                Показать содержимое
                                            </a>
                                        </div>
                                    <?php endif; ?>

                                    <?php if ($message['body']): ?>
                                        <div class="email-content mt-4 <?php echo $message['isHTML'] ? 'html-content' : 'plain-text'; ?>">
                                            <?php if ($message['isHTML']): ?>
                                                <div class="html-email-content">
                                                    <?php echo $message['body']; ?>
                                                </div>
                                            <?php else: ?>
                                                <pre class="whitespace-pre-wrap font-mono text-sm">
                                                    <?php echo htmlspecialchars($message['body']); ?>
                                                </pre>
                                            <?php endif; ?>
                                        </div>
                                    <?php endif; ?>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </main>

    <script>
        // Обработка внешних ссылок
        document.addEventListener('DOMContentLoaded', function() {
            document.querySelectorAll('.email-content a').forEach(function(link) {
                if (link.hostname !== window.location.hostname) {
                    link.setAttribute('target', '_blank');
                    link.setAttribute('rel', 'noopener noreferrer');
                }
            });

            // Исправление относительных путей изображений
            document.querySelectorAll('.email-content img[src^="/"]').forEach(function(img) {
                img.setAttribute('src', 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7');
            });
        });
    </script>
</body>
</html>