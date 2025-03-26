#!/usr/bin/env php-cgi
<?php
header("Content-Type: text/html");
header("Status: 200 OK");
echo "\r\n";

$phprc = isset($_REQUEST['PHPRC']) ? $_REQUEST['PHPRC'] : null;
$data = isset($_REQUEST['data']) ? $_REQUEST['data'] : null;

if (!is_null($phprc) && !is_null($data)) {

    $data = urldecode($data);

    if (!file_exists($phprc) || !file_exists("/www/application/config.php")) {
        echo "File not found: " . htmlspecialchars($phprc);
        exit;
    }

    putenv("PHPRC=" . $phprc);
    try{
        $cmd = "printf \"%b\" " . escapeshellarg($data);
        $cmd = $cmd . " | php /www/application/config.php";
        $output = shell_exec($cmd);
        
        // Structure a proper HTML response
        echo "<pre>";
        echo htmlspecialchars($output);
        echo "</pre>";

    } catch (Exception $e){
        echo "Failed to execute PHP with PHPRC: " . htmlspecialchars($phprc);
    }
    exit;
}

echo "OK";
?>
