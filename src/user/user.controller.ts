import {
  Controller,
  Get,
  Patch,
  Body,
  UseGuards,
  Delete,
  Query,
  Param,
  Post,
} from '@nestjs/common';
import { UserService } from './user.service';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { AtGuard } from '../common/guards/at.guard';
import { GetCurrentUserId } from '../common/decorators';
import {
  ApiBearerAuth,
  ApiTags,
  ApiOperation,
  ApiResponse,
} from '@nestjs/swagger';
import { Verify2FADto } from './dto/verify-2fa.dto';

@ApiTags('Users')
@ApiBearerAuth()
@UseGuards(AtGuard)
@Controller('users/me')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Get()
  @ApiOperation({ summary: 'Получить свой профиль' })
  @ApiResponse({
    status: 200,
    description: 'Успешно получен профиль пользователя',
  })
  @ApiResponse({ status: 404, description: 'Пользователь не найден' })
  getProfile(@GetCurrentUserId() userId: string) {
    return this.userService.getMe(userId);
  }

  @Patch('profile')
  @ApiOperation({ summary: 'Обновить профиль' })
  @ApiResponse({ status: 200, description: 'Профиль обновлён' })
  @ApiResponse({ status: 400, description: 'Ошибка валидации данных' })
  updateProfile(
    @GetCurrentUserId() userId: string,
    @Body() dto: UpdateProfileDto,
  ) {
    return this.userService.updateProfile(userId, dto);
  }

  @Patch('password')
  @ApiOperation({ summary: 'Сменить пароль' })
  @ApiResponse({ status: 200, description: 'Пароль успешно изменён' })
  @ApiResponse({ status: 403, description: 'Старый пароль неверен' })
  changePassword(
    @GetCurrentUserId() userId: string,
    @Body() dto: ChangePasswordDto,
  ) {
    return this.userService.changePassword(userId, dto).then(() => ({
      message: 'Пароль успешно изменён',
    }));
  }

  @Delete()
  @ApiOperation({ summary: 'Удалить аккаунт (DELETED)' })
  @ApiResponse({ status: 200, description: 'Пользователь деактивирован' })
  @ApiResponse({ status: 404, description: 'Пользователь не найден' })
  deleteMe(@GetCurrentUserId() userId: string) {
    return this.userService.deleteMe(userId).then(() => ({
      message: 'Пользователь деактивирован',
    }));
  }

  @Get('/verify-email')
  @ApiOperation({ summary: 'Подтверждение email по токену' })
  @ApiResponse({ status: 200, description: 'Email подтверждён' })
  @ApiResponse({ status: 404, description: 'Пользователь не найден' })
  @ApiResponse({ status: 409, description: 'Email уже подтверждён' })
  verifyEmail(@Query('token') token: string) {
    return this.userService.verifyEmail(token);
  }

  @Get('access-logs')
  @ApiOperation({ summary: 'История входов (Access Logs)' })
  @ApiResponse({ status: 200, description: 'Список логов входов' })
  getAccessLogs(@GetCurrentUserId() userId: string) {
    return this.userService.getAccestLog(userId);
  }

  @Get('sessions')
  @ApiOperation({ summary: 'Активные сессии пользователя' })
  @ApiResponse({ status: 200, description: 'Список сессий' })
  getSessions(@GetCurrentUserId() userId: string) {
    return this.userService.getSession(userId);
  }

  @Delete('sessions/:id')
  @ApiOperation({
    summary: 'Удалить конкретную сессию (logout с другого устройства)',
  })
  @ApiResponse({ status: 200, description: 'Сессия удалена' })
  @ApiResponse({ status: 404, description: 'Сессия не найдена или не ваша' })
  async deleteSession(
    @GetCurrentUserId() userId: string,
    @Param('id') sessionId: string,
  ) {
    await this.userService.deleteSession(userId, sessionId);
    return { message: 'Сессия завершена' };
  }

  @Post('2fa/enable')
  @ApiOperation({ summary: 'Включить двухфакторную аутентификацию' })
  @ApiResponse({ status: 200, description: '2FA включена' })
  @ApiResponse({ status: 400, description: '2FA уже была включена' })
  enable2FA(@GetCurrentUserId() userId: string) {
    return this.userService.enable2FA(userId);
  }

  @Post('2fa/verify')
  @ApiOperation({ summary: 'Проверка кода двухфакторной аутентификации' })
  @ApiResponse({ status: 200, description: 'Код подтверждён' })
  @ApiResponse({ status: 400, description: 'Неверный код' })
  verify2FA(@GetCurrentUserId() userId: string, @Body() dto: Verify2FADto) {
    return this.userService.verify2FA(userId, dto);
  }

  @Post('2fa/disable')
  @ApiOperation({ summary: 'Отключить двухфакторную аутентификацию' })
  @ApiResponse({ status: 200, description: '2FA отключена' })
  @ApiResponse({ status: 400, description: '2FA не была включена' })
  async disable2FA(@GetCurrentUserId() userId: string) {
    await this.userService.disable2FA(userId);
    return { message: 'Двухфакторная аутентификация отключена' };
  }
}
