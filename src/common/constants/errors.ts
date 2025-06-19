export const TOKEN_ERROR = {
  refreshTokenInvalid: 'Токен обновления недействителен или истёк',
  accessTokenInvalid: 'Токен доступа недействителен или истёк',
};
// src/common/constants/errors.ts

export const USER_ERRORS = {
  NOT_FOUND: 'Пользователь не найден',
  EMAIL_NOT_FOUND: (email: string) => `Пользователь с email ${email} не найден`, // Новое сообщение об ошибке
  ID_NOT_FOUND: (id: string) => `Пользователь с ID ${id} не найден`, // Новое сообщение об ошибке
  EMAIL_ALREADY_EXISTS: (email: string) =>
    `Пользователь с email ${email} уже существует`,
  OLD_PASSWORD_INCORRECT: 'Старый пароль неверен',
  EMAIL_ALREADY_VERIFIED: 'Email уже подтверждён',
  SESSION_NOT_FOUND: 'Сессия не найдена',
  TWO_FA_NOT_ENABLED: 'Двухфакторная аутентификация не включена',
  TWO_FA_INCORRECT: 'Неверный код двухфакторной аутентификации',
};

export const AUTH_ERRORS = {
  INVALID_CREDENTIALS: 'Неверный email или пароль',
  EMAIL_NOT_VERIFIED: 'Email не подтверждён',
  ACCESS_DENIED: 'Доступ запрещён',
};

export const GENERAL_ERRORS = {
  UNEXPECTED: 'Произошла неожиданная ошибка. Попробуйте позже.',
};
