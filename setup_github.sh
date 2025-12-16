#!/bin/bash
# Скрипт для автоматического создания репозитория на GitHub

set -e

REPO_NAME="ip-aggregator"
DESCRIPTION="Optimal IP address aggregation with minimal over-blocking - Red-Blue Set Cover solver"

echo "🚀 Настройка GitHub репозитория для IP Aggregator"
echo ""

# Проверка наличия gh CLI
if ! command -v gh &> /dev/null; then
    echo "⚠️  GitHub CLI (gh) не установлен."
    echo ""
    echo "Установка через Homebrew..."
    if command -v brew &> /dev/null; then
        brew install gh
    else
        echo "❌ Homebrew не найден. Установите GitHub CLI вручную:"
        echo "   brew install gh"
        echo "   или следуйте инструкциям: https://cli.github.com/"
        exit 1
    fi
fi

# Проверка авторизации
if ! gh auth status &> /dev/null; then
    echo "🔐 Требуется авторизация в GitHub"
    echo "Выполните: gh auth login"
    echo ""
    read -p "Выполнить авторизацию сейчас? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        gh auth login
    else
        echo "Выполните авторизацию вручную: gh auth login"
        exit 1
    fi
fi

echo ""
echo "📦 Создание репозитория на GitHub..."

# Создание репозитория
gh repo create "$REPO_NAME" \
    --public \
    --description "$DESCRIPTION" \
    --source=. \
    --remote=origin \
    --push

echo ""
echo "✅ Репозиторий успешно создан!"
echo ""
echo "🔗 URL: https://github.com/$(gh api user --jq .login)/$REPO_NAME"
echo ""
echo "Рекомендуется добавить теги на странице репозитория:"
echo "  ip-aggregation, cidr, optimization, python, network-security, set-cover"

