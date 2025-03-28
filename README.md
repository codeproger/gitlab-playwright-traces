# GitLab Artifacts Retriever

Утилита на Golang для получения артефактов из директории `/output/trace` указанной GitLab job по её ID.

## Возможности

- Получение списка всех артефактов из директории `/output/trace` для указанной job в GitLab (требуется ID проекта и ID джобы)
- Отображение прямых ссылок для скачивания каждого артефакта
- Поддержка как gitlab.com, так и self-hosted GitLab инсталляций
- Возможность запуска как нативного приложения, так и в Docker контейнере

## Требования

Для локального запуска:
- Go 1.18 или выше
- Доступ к GitLab API (Personal Access Token)
- ID проекта в GitLab
- ID джобы в GitLab

Для запуска в Docker:
- Docker

## Установка

### Клонирование репозитория

```bash
git clone https://your-repository-url/gitlab-artifacts-retriever.git
cd gitlab-artifacts-retriever
```

### Настройка переменных окружения

Скопируйте пример `.env` файла и настройте его под свои нужды:

```bash
cp .env.example .env
```

Отредактируйте `.env` файл, указав ваш GitLab API token:

```
GITLAB_TOKEN=your_personal_access_token_here
GITLAB_URL=https://gitlab.com  # или URL вашего GitLab сервера
```

## Использование

### Запуск в Docker (основной способ)

1. Соберите Docker образ:
   ```bash
   make build
   ```

2. Запустите приложение в контейнере:
   ```bash
   make run JOB_ID=12345 PROJECT_ID=67890
   ```

### Локальный запуск (опционально)

Если вам нужно запустить приложение локально:

1. Извлеките бинарный файл из Docker образа:
   ```bash
   make extract
   ```

2. Запустите извлеченный бинарный файл:
   ```bash
   ./gitlab-artifacts-retriever --job=12345 --project=67890 --token=your_gitlab_token
   ```

### Ручной запуск

```bash
./gitlab-artifacts-retriever --job=12345 --project=67890 --token=your_gitlab_token --url=https://gitlab.com
```

## Параметры командной строки

| Параметр | Описание | Значение по умолчанию |
|----------|----------|-----------------------|
| `--job`, `-j` | ID GitLab job (обязательный) | - |
| `--project`, `-p` | ID GitLab проекта (обязательный) | - |
| `--token`, `-t` | GitLab API token | Значение из переменной окружения `GITLAB_TOKEN` |
| `--url`, `-u` | URL GitLab инстанса | `https://gitlab.com` |

## Пример вывода

```
Found 3 artifacts in /output/trace for job 12345:

1. test-results.xml
   Path: output/trace/test-results.xml
   URL: https://gitlab.com/api/v4/jobs/12345/artifacts/output/trace/test-results.xml

2. coverage.html
   Path: output/trace/coverage.html
   URL: https://gitlab.com/api/v4/jobs/12345/artifacts/output/trace/coverage.html

3. performance.json
   Path: output/trace/performance.json
   URL: https://gitlab.com/api/v4/jobs/12345/artifacts/output/trace/performance.json
```

## Структура проекта

```
.
├── .env                # Файл с переменными окружения
├── Dockerfile          # Файл для сборки Docker образа
├── Makefile            # Файл с командами для сборки и запуска
├── README.md           # Документация проекта
├── go.mod              # Файл с зависимостями Go
└── main.go             # Исходный код приложения
```

## Makefile команды

| Команда | Описание |
|---------|----------|
| `make build` | Сборка Docker образа |
| `make run JOB_ID=12345 PROJECT_ID=67890` | Запуск приложения в Docker |
| `make extract` | Извлечение бинарного файла из Docker образа |
| `make clean` | Очистка скомпилированных файлов и Docker образов |
| `make help` | Отображение доступных команд |

## Лицензия

[MIT](LICENSE)