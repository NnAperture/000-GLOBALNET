# Django Device Authentication

Проект проверяет, что клиент владеет приватным Ed25519-ключом, зарегистрированным на сервере.

## Установка и запуск

Требуется Python 3.11+.

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

Админка: http://127.0.0.1:8000/admin/\n\nДля локального запуска DEBUG по умолчанию включён. В production обязательно задайте `DJANGO_DEBUG=False`, `DJANGO_SECRET_KEY` и `DJANGO_ALLOWED_HOSTS` через переменные окружения.

## Выдать код регистрации

В админке откройте «Устройства → Коды регистрации → Добавить». Укажите Label и Expires at (будущее время), сохраните. Сырой одноразовый код будет показан в сообщении админки один раз. В БД хранится только SHA-256-хеш кода.

## Запустить клиент

Во втором терминале из корня проекта:

```bash
pip install requests cryptography
python devices/client.py register --server http://127.0.0.1:8000 --name "My PC" --enrollment-token ВАШ_КОД
python devices/client.py verify --server http://127.0.0.1:8000
```

Клиент создаёт `device_private_key.pem` (секретный приватный ключ) и `device.json` (ID и fingerprint). Никогда не передавайте приватный ключ серверу и не публикуйте его.

## API

- `GET /api/health/` — проверка сервиса.
- `POST /api/register/` — регистрация публичного ключа с одноразовым кодом. JSON: `name`, `public_key` (PEM), `enrollment_token`.
- `POST /api/challenge/` — JSON: `device_id`. Возвращает короткоживущий nonce и `message_to_sign`.
- `POST /api/verify/` — JSON: `challenge_id`, `signature` (Base64 подписи сообщения).

Подписываемая строка: `device-auth:v1:{device_id}:{challenge_id}:{nonce}`. Challenge живёт 2 минуты и принимается только один раз.

## Администрирование

В разделе «Устройства» можно просматривать устройства, блокировать и активировать их. Блокировка сразу запрещает получать новые challenge и проходить проверку.

## Важные ограничения и production

Это подтверждение владения ключом, а не доказательство физической уникальности компьютера. Если злоумышленник скопирует `device_private_key.pem`, он сможет аутентифицироваться на другом компьютере. Для более сильной привязки храните ключ в TPM или системном защищённом хранилище (DPAPI, Keychain, Secret Service).

Перед публикацией:
1. Обязательно используйте HTTPS.
2. Установите уникальный `DJANGO_SECRET_KEY`, `DJANGO_DEBUG=False` и корректный `DJANGO_ALLOWED_HOSTS`.
3. Для реальной нагрузки используйте PostgreSQL.
4. Ограничьте доступ к админке, настройте rate limiting, логирование и резервное копирование.
5. В примере приватный ключ хранится незашифрованным файлом для простоты. Защитите его правами доступа или замените на системное хранилище ключей.
6. Проведите аудит безопасности перед production.
\n\n## Тесты\n\n```bash\npython manage.py test devices\n```\n