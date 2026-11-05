@echo off
chcp 65001 >nul
echo ======================================
echo       راه‌اندازی سامانه هویار
echo ======================================
echo.
if not exist .env (
  copy .env.example .env >nul
  echo فایل .env ساخته شد. ابتدا JWT_SECRET و ADMIN_PASSWORD را در آن تنظیم کنید.
  echo رمز مدیر باید حداقل ۱۲ نویسه داشته باشد.
  echo.
  pause
  exit /b 0
)
echo وابستگی‌ها را نصب می‌کنیم...
call npm install
if errorlevel 1 exit /b 1
echo.
echo آدرس ورود مدیر: http://localhost:3000/admin-login.html
echo.
call npm start
