<?php
// VULNERABLE ON PURPOSE: no extension allow-list, no MIME check, and the
// uploaded filename is used as-is -- an attacker can upload a .php file
// and Apache will happily execute it out of uploads/.
$target_dir = __DIR__ . "/uploads/";

if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_FILES["photo"])) {
    $filename = basename($_FILES["photo"]["name"]);
    $target_file = $target_dir . $filename;

    if (move_uploaded_file($_FILES["photo"]["tmp_name"], $target_file)) {
        echo "<p>Uploaded to: <a href=\"uploads/" . htmlspecialchars($filename) . "\">uploads/" . htmlspecialchars($filename) . "</a></p>";
    } else {
        echo "<p>Upload failed.</p>";
    }
} else {
    echo "<p>No file received.</p>";
}
