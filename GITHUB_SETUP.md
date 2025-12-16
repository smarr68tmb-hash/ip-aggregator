# Инструкция по созданию репозитория на GitHub

## Вариант 1: Через веб-интерфейс GitHub (рекомендуется)

1. Перейдите на https://github.com/new
2. Заполните форму:
   - **Repository name**: `ip-aggregator` (или любое другое имя)
   - **Description**: `Optimal IP address aggregation with minimal over-blocking - Red-Blue Set Cover solver`
   - Выберите **Public** или **Private**
   - **НЕ** создавайте README, .gitignore или лицензию (они уже есть)
3. Нажмите **Create repository**
4. Выполните команды, которые GitHub покажет (или используйте команды ниже):

```bash
cd /Users/a1111/IP
git remote add origin https://github.com/YOUR_USERNAME/ip-aggregator.git
git branch -M main
git push -u origin main
```

Замените `YOUR_USERNAME` на ваш GitHub username.

## Вариант 2: Через GitHub CLI (если установлен)

Если у вас установлен GitHub CLI (`gh`), выполните:

```bash
cd /Users/a1111/IP
gh repo create ip-aggregator --public --source=. --remote=origin --push
```

Если `gh` не установлен, установите его:
- macOS: `brew install gh`
- Затем: `gh auth login`

## Вариант 3: Через GitHub API (если есть токен)

Если у вас есть GitHub Personal Access Token:

```bash
cd /Users/a1111/IP
# Создать репозиторий через API
curl -X POST \
  -H "Authorization: token YOUR_GITHUB_TOKEN" \
  -H "Accept: application/vnd.github.v3+json" \
  https://api.github.com/user/repos \
  -d '{"name":"ip-aggregator","description":"Optimal IP address aggregation with minimal over-blocking","private":false}'

# Добавить remote и запушить
git remote add origin https://github.com/YOUR_USERNAME/ip-aggregator.git
git branch -M main
git push -u origin main
```

## После создания репозитория

Рекомендуется добавить:
- **Topics/Теги**: `ip-aggregation`, `cidr`, `optimization`, `python`, `network-security`, `set-cover`
- **Описание**: "Optimal IP address aggregation with minimal over-blocking. Solves Red-Blue Set Cover problem to compress IP addresses to limited number of CIDR rules."

## Проверка

После push проверьте, что все файлы загружены:
- `ip_aggregator.py` - основной скрипт
- `generate_test_data.py` - генератор тестовых данных
- `README.md` - документация
- `QUICKSTART.md` - быстрый старт
- `requirements.txt` - зависимости
- `.gitignore` - игнорируемые файлы

