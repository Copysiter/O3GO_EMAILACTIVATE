<?php
ob_start();
session_start();
require_once '../config.php';
require_once '../functions.php';

error_reporting(0);
ini_set('display_errors', '0');

header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');

try {
    $mysqli = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    if ($mysqli->connect_error) {
        throw new Exception('Database connection error');
    }
    $mysqli->set_charset('utf8mb4');

    $stmt = $mysqli->prepare("SELECT email, assoc_password FROM users ORDER BY RAND() LIMIT 1");
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();

    if (!$user) {
        throw new Exception('E-mail not found');
    }

    echo json_encode([
        'success' => true,
        'email' => $user['email'],
        'password' => $user['assoc_password']
    ], JSON_UNESCAPED_UNICODE);

} catch (Exception $e) {
    error_log("Error in mail fetcher: " . $e->getMessage());
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage()
    ]);
}