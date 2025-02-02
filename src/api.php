<?php
ob_start();
session_start();
require_once 'config.php';
require_once 'functions.php';

error_reporting(0);
ini_set('display_errors', '0');

header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');

function extractLinks($content) {
    $links = [];
    preg_match_all('/<a[^>]+href=([\'"])(?<href>.+?)\1[^>]*>/i', $content, $matches);
    if (!empty($matches['href'])) {
        $links = array_merge($links, $matches['href']);
    }
    
    preg_match_all('/\b(?:https?:\/\/|www\.)[^\s<>\[\]{}"\']*/i', $content, $matches);
    if (!empty($matches[0])) {
        $links = array_merge($links, $matches[0]);
    }
    
    $links = array_unique(array_map(function($link) {
        return trim($link, " \t\n\r\0\x0B,.");
    }, $links));
    
    return array_values(array_filter($links));
}
function cleanContent($content) {
    $originalContent = $content;
    
    $content = preg_replace('/<style[^>]*>.*?<\/style>/si', '', $content);
    $content = preg_replace('/<script[^>]*>.*?<\/script>/si', '', $content);
    $content = preg_replace('/Content-Type:\s*[^\n]+/i', '', $content);
    $content = preg_replace('/Content-Transfer-Encoding:\s*[^\n]+/i', '', $content);
    $content = preg_replace('/This is a multi-part message[^\n]+/i', '', $content);
    $content = preg_replace('/--=?[a-zA-Z0-9\'_+\-]+/m', '', $content);
    $content = preg_replace('/Unsubscribe From This List.*$/im', '', $content);
    $content = preg_replace('/If you cannot read this email.*$/im', '', $content);
    
    $links = extractLinks($originalContent);
    $content = strip_tags($content);
    $content = preg_replace('/\s+/', ' ', $content);
    
    $encoding = mb_detect_encoding($content, ['UTF-8', 'Windows-1251', 'KOI8-R'], true);
    if ($encoding && $encoding !== 'UTF-8') {
        $content = mb_convert_encoding($content, 'UTF-8', $encoding);
    }
    
    $content = html_entity_decode($content, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    
    return [
        'text' => trim($content),
        'links' => $links
    ];
}
function getMessageContent($imap, $msgNum) {
    $content = imap_body($imap, $msgNum);
    $content = quoted_printable_decode($content);
    return cleanContent($content);
}

function updateStatistics($mysqli, $user_id, $email, $messages) {
    try {
        $stmt = $mysqli->prepare("INSERT INTO user_stats (user_id, emails_downloaded, last_activity) 
                                 VALUES (?, ?, NOW()) 
                                 ON DUPLICATE KEY UPDATE 
                                 emails_downloaded = emails_downloaded + ?, 
                                 last_activity = NOW()");
        $count = count($messages);
        $stmt->bind_param("iii", $user_id, $count, $count);
        $stmt->execute();

        $stmt = $mysqli->prepare("INSERT INTO daily_stats (date, total_emails, active_users) 
                                VALUES (CURDATE(), ?, 1)
                                ON DUPLICATE KEY UPDATE 
                                total_emails = total_emails + ?,
                                active_users = (
                                    SELECT COUNT(DISTINCT user_id) 
                                    FROM user_stats 
                                    WHERE DATE(last_activity) = CURDATE()
                                )");
        $stmt->bind_param("ii", $count, $count);
        $stmt->execute();
        foreach ($messages as $message) {
            if (!empty($message['from'])) {
                $domain = explode('@', $message['from'])[1] ?? '';
                if ($domain) {
                    $stmt = $mysqli->prepare("INSERT INTO email_domain_stats (domain, email_count) 
                                            VALUES (?, 1)
                                            ON DUPLICATE KEY UPDATE 
                                            email_count = email_count + 1");
                    $stmt->bind_param("s", $domain);
                    $stmt->execute();
                }
            }
        }
    } catch (Exception $e) {
        error_log("Error updating statistics: " . $e->getMessage());
    }
}

try {
    if (!isset($_GET['email'], $_GET['password'])) {
        throw new Exception('Missing credentials');
    }

    $loginEmail = trim($_GET['email']);
    $assoc_password = trim($_GET['password']);
    $shouldDelete = isset($_GET['delete']) && $_GET['delete'] === '1';
    
    if (!filter_var($loginEmail, FILTER_VALIDATE_EMAIL)) {
        throw new Exception('Invalid email format');
    }
    $mysqli = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    if ($mysqli->connect_error) {
        throw new Exception('Database connection error');
    }
    $mysqli->set_charset('utf8mb4');
   
    $stmt = $mysqli->prepare("SELECT * FROM users WHERE email = ? AND assoc_password = ? LIMIT 1");
    $stmt->bind_param("ss", $loginEmail, $assoc_password);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();
   
    if (!$user) {
        throw new Exception('Authentication failed');
    }

    $messages = [];
    $server = '{imap.yandex.ru:993/imap/ssl}';
    $loginEmailLower = strtolower($loginEmail);

    foreach (['INBOX', 'Spam'] as $folder) {
        $imap = @imap_open($server . $folder, $loginEmail, $user['imap_password']);
        if (!$imap) {
            error_log("IMAP connection error for folder $folder: " . imap_last_error());
            continue;
        }
        $emails = imap_search($imap, 'ALL');
       
        if ($emails) {
            foreach ($emails as $msgNum) {
                try {
                    $header = @imap_headerinfo($imap, $msgNum);
                    if (!$header || empty($header->to)) continue;
                   
                    $isForUser = false;
                    foreach ($header->to as $to) {
                        $toEmail = strtolower($to->mailbox . '@' . $to->host);
                        if ($toEmail === $loginEmailLower) {
                            $isForUser = true;
                            break;
                        }
                    }
                   
                    if (!$isForUser) continue;
                   
                    $messageContent = getMessageContent($imap, $msgNum);
                   
                    $from = '';
                    if (isset($header->from[0])) {
                        $from = $header->from[0]->mailbox . '@' . $header->from[0]->host;
                    }

                    $messages[] = [
                        'id' => $msgNum,
                        'folder' => $folder,
                        'subject' => imap_utf8($header->subject ?? '(Без темы)'),
                        'from' => $from,
                        'to' => $loginEmail,
                        'date' => date('Y-m-d H:i:s', strtotime($header->date)),
                        'unread' => !isset($header->Seen),
                        'content' => $messageContent['text'],
                        'links' => $messageContent['links']
                    ];

                    if ($shouldDelete) {
                        imap_delete($imap, $msgNum);
                    }
                } catch (Exception $e) {
                    error_log("Error processing message $msgNum: " . $e->getMessage());
                    continue;
                }
            }
           
            if ($shouldDelete) {
                imap_expunge($imap);
            }
        }
        imap_close($imap);
    }

    updateStatistics($mysqli, $user['id'], $loginEmail, $messages);

    echo json_encode([
        'success' => true,
        'messages' => $messages,
        'total' => count($messages),
        'email' => $loginEmail
    ], JSON_UNESCAPED_UNICODE);

} catch (Exception $e) {
    error_log("Error in mail fetcher: " . $e->getMessage());
    echo json_encode([
        'success' => false,
        'messages' => [],
        'total' => 0,
        'error' => $e->getMessage()
    ]);
}