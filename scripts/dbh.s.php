<?php
$dBServername = "localhost";
$dBUsername = "root";
$dBPassword = "";
$dBName = "userProfile";

// Create connection
$conn = mysqli_connect($dBServername, $dBUsername, $dBPassword, $dBName);

// Check connection
if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
    header("Location: ../signup.html?dbh=failed");
}
