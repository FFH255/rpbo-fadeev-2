<?php

if( isset( $_GET[ 'Login' ] ) ) {
	$user = $_GET[ 'username' ];

	$pass = $_GET[ 'password' ];

	/* (1) Небезопасное хэширование пароля (CWE-327) Использование функции md5() устаревшая практика, так как MD5 считается небезопасным и подвержен атакам по подбору */
	$pass = md5( $pass );

	/* (2) SQL-инъекция (CWE-89) - $user и $pass включены в SQL-запрос без предварительной фильтрации или экранирования */
	$query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";

	/* (3) Потенциальный риск раскрытия ошибок (CWE-209) */
	$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

	if( $result && mysqli_num_rows( $result ) == 1 ) {
		// Get users details
		$row    = mysqli_fetch_assoc( $result );
		$avatar = $row["avatar"];

		/* (4) Уязвимость к межсайтовому скриптингу (XSS) (CWE-79) - Переменная $user вставляется в HTML-код без какой-либо очистки или экранирования */
		$html .= "<p>Welcome to the password protected area {$user}</p>";
		$html .= "<img src=\"{$avatar}\" />";
	}
	else {
		// Login failed
		$html .= "<pre><br />Username and/or password incorrect.</pre>";
	}

	((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}


/* (5) Код не ограничивает количество попыток входа, что позволяет злоумышленнику применять метод перебора (brute-force) для подбора пароля. Это существенно упрощает атаку на учетные записи пользователей. */

?>
