<?php
session_start();

$attempts_limit = 5;
$attempts_time_window = 60;

if (!isset($_SESSION['login_attempts'])) {
    $_SESSION['login_attempts'] = [];
}

$_SESSION['login_attempts'] = array_filter($_SESSION['login_attempts'], function($timestamp) use ($attempts_time_window) {
    return $timestamp > (time() - $attempts_time_window);
});

if (count($_SESSION['login_attempts']) >= $attempts_limit) {
    die('<pre>Too many login attempts. Please try again later.</pre>');
}

if (isset($_GET['Login'])) {
    $_SESSION['login_attempts'][] = time();

    $mysqli = $GLOBALS["___mysqli_ston"];
    
    $user = mysqli_real_escape_string($mysqli, $_GET['username']);
    
    $pass = $_GET['password'];
    $hashed_pass = password_hash($pass, PASSWORD_BCRYPT);

    $query = "SELECT * FROM `users` WHERE user = ? AND password = ?";
    $stmt = mysqli_prepare($mysqli, $query);
    mysqli_stmt_bind_param($stmt, "ss", $user, $hashed_pass);

    if (mysqli_stmt_execute($stmt)) {
        $result = mysqli_stmt_get_result($stmt);
        
        if ($result && mysqli_num_rows($result) == 1) {
            $row = mysqli_fetch_assoc($result);
            $avatar = htmlspecialchars($row["avatar"]);
            
            $html = "<p>Welcome to the password protected area " . htmlspecialchars($user) . "</p>";
            $html .= "<img src=\"{$avatar}\" />";
            
            $_SESSION['login_attempts'] = [];
        } else {
            $html = "<pre><br />Username and/or password incorrect.</pre>";
        }
    } else {
        error_log(mysqli_error($mysqli));
        $html = "<pre>Database error.</pre>";
    }
    
    mysqli_stmt_close($stmt);
    mysqli_close($mysqli);
}
?>