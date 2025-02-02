<?php
require_once 'config.php';

class Security {
   private $db;
   private $max_attempts;
   private $block_time;

   public function __construct() {
       $this->db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
       $this->max_attempts = MAX_LOGIN_ATTEMPTS;
       $this->block_time = BLOCK_TIME;

       if ($this->db->connect_error) {
           throw new Exception("Database connection failed");
       }
   }

   // [Весь существующий код класса Security остается без изменений]
   
   public function __destruct() {
       $this->db->close();
   }
}

// IMAP функции
function hasAttachments($structure) {
   if (isset($structure->parts)) {
       foreach ($structure->parts as $part) {
           if ($part->ifdisposition && strtolower($part->disposition) === 'attachment') {
               return true;
           }
           if (isset($part->parts)) {
               return hasAttachments($part);
           }
       }
   }
   return false;
}

function getMessageBody($imap, $msgNum, $structure) {
   if (!isset($structure->parts)) {
       $body = imap_body($imap, $msgNum);
       return nl2br(decodeBody($body, $structure->encoding));
   }

   $plainText = '';
   $html = '';

   foreach ($structure->parts as $partNum => $part) {
       if ($part->type === 0) { // text
           $content = imap_fetchbody($imap, $msgNum, $partNum + 1);
           $content = decodeBody($content, $part->encoding);
           
           if (isset($part->subtype)) {
               if (strtolower($part->subtype) === 'plain') {
                   $plainText .= $content;
               } elseif (strtolower($part->subtype) === 'html') {
                   $html .= $content;
               }
           }
       } elseif ($part->type === 1) { // multipart
           foreach ($part->parts as $subPartNum => $subPart) {
               if ($subPart->type === 0) {
                   $partNum = ($partNum + 1) . '.' . ($subPartNum + 1);
                   $content = imap_fetchbody($imap, $msgNum, $partNum);
                   $content = decodeBody($content, $subPart->encoding);
                   
                   if (isset($subPart->subtype)) {
                       if (strtolower($subPart->subtype) === 'plain') {
                           $plainText .= $content;
                       } elseif (strtolower($subPart->subtype) === 'html') {
                           $html .= $content;
                       }
                   }
               }
           }
       }
   }

   return $html ?: nl2br($plainText) ?: '(Нет содержимого)';
}

function decodeBody($body, $encoding) {
   if (!$body) return '';
   
   switch ($encoding) {
       case 3: // BASE64
           $body = base64_decode($body);
           break;
       case 4: // QUOTED-PRINTABLE
           $body = quoted_printable_decode($body);
           break;
   }

   // Определение и конвертация кодировки
   $encodings = ['UTF-8', 'Windows-1251', 'KOI8-R', 'CP866', 'ISO-8859-5'];
   foreach ($encodings as $encoding) {
       $converted = @mb_convert_encoding($body, 'UTF-8', $encoding);
       if ($converted) {
           $body = $converted;
           break;
       }
   }
   
   return $body;
}

function decodeMimeStr($string) {
   if (!$string) return '';
   $decoded = iconv_mime_decode($string, 0, "UTF-8");
   return $decoded ?: $string;
}

function getAttachments($imap, $msgNum, $structure) {
   $attachments = [];
   
   if (isset($structure->parts)) {
       foreach ($structure->parts as $partNum => $part) {
           if ($part->ifdisposition && 
               strtolower($part->disposition) === 'attachment') {
               
               $filename = '';
               if (isset($part->dparameters)) {
                   foreach ($part->dparameters as $param) {
                       if (strtolower($param->attribute) === 'filename') {
                           $filename = decodeMimeStr($param->value);
                       }
                   }
               }
               
               if (!$filename && isset($part->parameters)) {
                   foreach ($part->parameters as $param) {
                       if (strtolower($param->attribute) === 'name') {
                           $filename = decodeMimeStr($param->value);
                       }
                   }
               }
               
               if ($filename) {
                   $attachments[] = [
                       'filename' => $filename,
                       'partNum' => $partNum + 1,
                       'encoding' => $part->encoding
                   ];
               }
           }
       }
   }
   
   return $attachments;
}
?>