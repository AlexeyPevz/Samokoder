# Развертывание Samokoder в Yandex Cloud

Это руководство поможет вам развернуть приложение Samokoder на виртуальной машине в Yandex Cloud с использованием управляемых сервисов.

## Шаг 1: Подготовка инфраструктуры в Yandex Cloud

1.  **Создайте виртуальную машину (ВМ):**
    *   Перейдите в раздел **Compute Cloud**.
    *   Создайте ВМ на базе Ubuntu 22.04 LTS.
    *   Рекомендуемые параметры: 2 vCPU, 4 ГБ RAM, 20 ГБ HDD/SSD.
    *   В настройках сети убедитесь, что у ВМ есть публичный IP-адрес и настроены группы безопасности, разрешающие входящий трафик на порты `22` (SSH), `80` (HTTP) и `443` (HTTPS).

2.  **Создайте управляемую базу данных PostgreSQL:**
    *   Перейдите в раздел **Managed Service for PostgreSQL**.
    *   Создайте новый кластер.
    *   Выберите версию PostgreSQL 15 или выше.
    *   В настройках укажите имя базы данных, имя пользователя и пароль.
    *   **Важно:** В настройках кластера разрешите доступ с вашей ВМ.

3.  **Создайте управляемую базу данных Redis:**
    *   Перейдите в раздел **Managed Service for Redis**.
    *   Создайте новый кластер.
    *   **Важно:** В настройках кластера разрешите доступ с вашей ВМ.

4.  **Создайте реестр для Docker-образов:**
    *   Перейдите в раздел **Container Registry**.
    *   Создайте новый реестр. Запишите его ID (`cr.p...`).

## Шаг 2: Настройка сервера (ВМ)

1.  **Подключитесь к ВМ по SSH:**
    ```bash
    ssh user@your_server_ip
    ```

2.  **Установите Docker и Docker Compose:**
    ```bash
    # Установка Docker
    sudo apt-get update
    sudo apt-get install -y docker.io
    sudo systemctl start docker
    sudo systemctl enable docker

    # Установка Docker Compose
    sudo curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
    ```

3.  **Установите Traefik (Reverse Proxy):**
    *   Мы будем использовать Traefik для управления доступом к нашим сервисам. Создайте на сервере папку `traefik` и в ней файлы `docker-compose.yml` и `traefik.yml`.
    *   *Более подробные инструкции по настройке Traefik можно найти в официальной документации.*

4.  **Клонируйте репозиторий проекта на ВМ:**
    ```bash
    git clone https://github.com/ваш_репозиторий/samokoder.git
    cd samokoder
    ```

5.  **Создайте файл `.env.prod` на ВМ:**
    *   Этот файл будет содержать все секреты для production.
    *   Создайте его в папке `samokoder` на сервере:
        ```bash
        nano .env.prod
        ```
    *   Заполните его по примеру ниже:
        ```env
        # URL вашей управляемой базы данных PostgreSQL
        PROD_DATABASE_URL="postgresql+asyncpg://user:password@host.mdb.yandexcloud.net:6432/dbname"

        # Хост вашего управляемого Redis
        PROD_REDIS_HOST="host.mdb.yandexcloud.net"

        # Секретные ключи приложения (сгенерируйте случайные строки)
        SECRET_KEY="your_super_secret_key_1"
        APP_SECRET_KEY="your_super_secret_key_2"

        # Домен, на котором будет работать приложение
        DOMAIN="your-domain.com"
        ```

## Шаг 3: Развертывание с локальной машины

На вашей локальной машине, где находится код проекта.

1.  **Установите Yandex Cloud CLI:**
    *   Следуйте [официальной инструкции](https://cloud.yandex.ru/docs/cli/quickstart).

2.  **Настройте скрипт `deploy_yc.sh`:**
    *   Откройте файл `deploy_yc.sh`.
    *   Укажите ваш `YC_REGISTRY_ID` (из Шага 1.4).
    *   Укажите `REMOTE_SERVER` в формате `user@your_server_ip`.

3.  **Сделайте скрипт исполняемым:**
    ```bash
    chmod +x deploy_yc.sh
    ```

4.  **Запустите развертывание:**
    ```bash
    ./deploy_yc.sh
    ```

Скрипт автоматически соберет Docker-образы, загрузит их в ваш реестр в Yandex Cloud, подключится к серверу и запустит/обновит приложение.

## Готово!

После успешного выполнения скрипта ваше приложение будет доступно по домену, который вы указали в переменной `DOMAIN`.
