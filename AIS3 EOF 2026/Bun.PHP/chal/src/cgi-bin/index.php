#!/usr/bin/php-cgi
<?php
if (isset($_GET["-s"])) {
    highlight_file(__FILE__);
    exit();
}

$name = htmlentities($_REQUEST["name"] ?? "World");

echo "<h1>Hello $name!</h1>\n";

