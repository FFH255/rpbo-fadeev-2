# Практическая работа 5
> Вариант 2. Номер студенческого билета 21Б0996

```c
\#include <stdio.h>
\#include <stdlib.h>
\#include <sys/types.h>
\#include <unistd.h>

void shell() {
    setreuid(geteuid(), geteuid());
    system("/bin/bash");
}

void sup() {
    printf("Hey dude ! Waaaaazzaaaaaaaa ?!\\n");
}

void main()
{ 
    int var;
    void (\*func)()=sup;
    char buf\[128\];
    fgets(buf,133,stdin);
    func();
}
```
## Настройка рабочего пространства
В качестве среды выполнения лабораторной работы запущен docker container с образом операционной системы Ubuntu с установленными утилитами для необходимого языка (gdb для отладки C).
Файл для динамической отладки копируется с хост-машины в volume Docker контейнера. [Dockerfile](./Dockerfile)

```Dockerfile
# Базовый образ Ubuntu
FROM ubuntu:18.04

# Установка необходимых утилит
RUN apt-get update && apt-get install -y \
    build-essential \
    gdb \
    nano \
    wget \
    curl \
    vim \
    python3 \
    python3-pip

# Установка дополнительных инструментов (по необходимости)
RUN apt-get install -y \
    strace \
    ltrace \
    valgrind \
    clang-tools

# Добавление рабочей директории
WORKDIR /workspace

# Копирование исходного кода внутрь контейнера
COPY ./src /workspace

CMD ["/bin/bash"]
```


Подключение к контейнеру с помощью docker exec

```bash
Home@MSK-H66QX93M2N low % docker exec -it 0cf8e7a5257e sh
# ls    
main.c
# 
```

Файл `main.c` скопирован в container.

## Необходимо провести динамическую отладку программного обеспечения с бинарной уязвимостью
### Компиляция программы

Команда ниже осуществляет компиляцию рассматривамой программы на языке C

```bash
gcc -g -o main main.c
```

Компиляция программы внутри контейнера 

```bash
root@75ffa644163a:/workspace# gcc -g -o main main.c
root@75ffa644163a:/workspace# ls
main  main.c
root@75ffa644163a:/workspace# 
```

### Успешное выполнение программы (буфер меньше 128 байт)

```bash
root@75ffa644163a:/workspace# gdb ./main
GNU gdb (Ubuntu 8.1.1-0ubuntu1) 8.1.1
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "aarch64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
---Type <return> to continue, or q <return> to quit---
Type "apropos word" to search for commands related to "word"...
Reading symbols from ./main...done.
(gdb) run
Starting program: /workspace/main 
123
Hey dude ! Waaaaazzaaaaaaaa ?!\n[Inferior 1 (process 43) exited normally]
(gdb) 
```

### Запуск программы с ошибкой (буфер больше 128 байт)

```bash
root@75ffa644163a:/workspace# gdb ./main
GNU gdb (Ubuntu 8.1.1-0ubuntu1) 8.1.1
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "aarch64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
---Type <return> to continue, or q <return> to quit---
Type "apropos word" to search for commands related to "word"...
Reading symbols from ./main...done.
(gdb) run
Starting program: /workspace/main 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
*** stack smashing detected ***: <unknown> terminated

Program received signal SIGABRT, Aborted.
__GI_raise (sig=sig@entry=6) at ../sysdeps/unix/sysv/linux/raise.c:51
51      ../sysdeps/unix/sysv/linux/raise.c: No such file or directory.
(gdb) 
```

## Проанализировать код и сделать кодревью, указав слабые места.

```c
void shell() {
    setreuid(geteuid(), geteuid());
    system("/bin/bash");
}
```
Эта функция меняет идентификатор пользователя процесса на эффективный идентификатор пользователя (EUID) и запускает оболочку Bash. Это может быть использовано для получения привилегий, если программа запущена от имени пользователя с повышенными правами.

```c
void sup() {
    printf("Hey dude ! Waaaaazzaaaaaaaa ?!\n");
}
```

Эта функция просто выводит сообщение на экран.

```c
void main() { 
    int var;
    void (*func)() = sup;
    char buf[128];
    fgets(buf, 133, stdin);
    func();
}
```

Функция main:
- Объявляется переменная `var`, указатель на функцию `func`, который инициализируется адресом функции `sup`.
- Создается массив `buf` размером 128 байт.
- Функция `fgets` считывает до 133 байт из стандартного ввода и помещает их в массив `buf`. Однако это потенциально опасно, так как размер буфера составляет только 128 байт.
- После этого вызывается функция `sup`.

Основная уязвимость в этой программе заключается в использовании функции `fgets` с неправильным размером буфера:

```c
fgets(buf, 133, stdin);
```

- Здесь программа пытается прочитать до 133 байт, но массив `buf` может вместить только 128 байт. Это приводит к переполнению буфера (buffer overflow).
- и пользователь введет более 128 символов, данные будут записаны за пределами выделенного массива, что может перезаписать другие части памяти, включая указатель на функцию `func`.
- Злоумышленник может воспользоваться этой уязвимостью для перезаписи указателя функции и перенаправления выполнения программы на функцию `shell`, что позволит ему получить доступ к оболочке с привилегиями.

## Предложить исправление для кода с целью избежать ошибки

```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

void shell() {
    setreuid(geteuid(), geteuid());
    system("/bin/bash");
}

void sup() {
    printf("Hey dude ! Waaaaazzaaaaaaaa ?!\n");
}

int main() // Изменено на int main для соответствия стандарту C
{ 
    int var;
    void (*func)() = sup;
    char buf[128];

    // Изменено на безопасное чтение с учетом размера буфера
    if (fgets(buf, sizeof(buf), stdin) == NULL) {
        perror("Error reading input");
        exit(EXIT_FAILURE);
    }

    func();
    return 0; // Возвращаем 0 для успешного завершения программы
}
```