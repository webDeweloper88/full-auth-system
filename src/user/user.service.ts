import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  BadRequestException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcryptjs';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { USER_ERRORS } from 'src/common/constants/errors';
import { AccessLog, LogEventType, User } from '@prisma/client';
import { Session } from '@prisma/client';
import { Verify2FADto } from './dto/verify-2fa.dto';
import { authenticator } from 'otplib';
import * as qrcode from 'qrcode';

@Injectable()
export class UserService {
  constructor(private prisma: PrismaService) {}

  async getMe(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        displayName: true,
        picktureUrl: true,
        role: true,
        accountStatus: true,
        emailVerified: true,
        createdAt: true,
        updatedAt: true,
      },
    });
    if (!user) throw new NotFoundException('Пользователь не найден');
    return user;
  }

  async updateProfile(userId: string, dto: UpdateProfileDto) {
    return this.prisma.user.update({
      where: { id: userId },
      data: {
        displayName: dto.displayName,
        picktureUrl: dto.pictureUrl,
      },
      select: {
        id: true,
        email: true,
        displayName: true,
        picktureUrl: true,
        role: true,
        accountStatus: true,
        updatedAt: true,
      },
    });
  }

  async changePassword(userId: string, dto: ChangePasswordDto): Promise<void> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) throw new NotFoundException(USER_ERRORS.ID_NOT_FOUND);

    const isMatch = await bcrypt.compare(dto.oldPassword, user.hash);
    if (!isMatch)
      throw new ForbiddenException(USER_ERRORS.OLD_PASSWORD_INCORRECT);

    const newHash = await bcrypt.hash(dto.newPassword, 10);
    await this.prisma.user.update({
      where: { id: userId },
      data: { hash: newHash },
    });
  }
  async deleteMe(userId: string): Promise<void> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new NotFoundException(USER_ERRORS.NOT_FOUND);
    }

    await this.prisma.user.update({
      where: { id: userId },
      data: {
        accountStatus: 'DELETED',
        emailVerified: false,
        hash: '',
        hashRt: null,
        resetPasswordToken: null,
        resetPasswordExpiresAt: null,
        twoFactorEnabled: false,
        twoFactorSecret: null,
        twoFactorExpiresAt: null,
      },
    });

    await this.prisma.session.deleteMany({
      where: { userId },
    });

    await this.prisma.accessLog.create({
      data: {
        userId,
        eventType: 'LOGOUT',
      },
    });
  }

  async verifyEmail(token: string): Promise<User> {
    const user = await this.prisma.user.findFirst({
      where: {
        emailVerificationToken: token,
      },
    });

    if (!user) {
      throw new NotFoundException(USER_ERRORS.NOT_FOUND);
    }
    if (user.emailVerified) {
      throw new ForbiddenException(USER_ERRORS.EMAIL_ALREADY_EXISTS);
    }
    const updatedUser = await this.prisma.user.update({
      where: { id: user.id },
      data: {
        emailVerified: true,
        emailVerificationToken: null,
        accountStatus: 'ACTIVE',
      },
    });

    await this.prisma.accessLog.create({
      data: {
        userId: updatedUser.id,
        eventType: 'EMAIL_VERIFICATION',
      },
    });
    return updatedUser;
  }

  async getAccestLog(userId: string): Promise<AccessLog[]> {
    const logs = await this.prisma.accessLog.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      select: {
        id: true,
        userId: true,
        ipAddress: true,
        userAgent: true,
        createdAt: true,
        eventType: true,
      },
    });

    if (!logs || logs.length === 0) {
      throw new NotFoundException('Access logs not found');
    }

    return logs;
  }

  async getSession(userId: string): Promise<Session[]> {
    const sessions = await this.prisma.session.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      select: {
        id: true,
        createdAt: true,
        updatedAt: true,
        userId: true,
        ipAddress: true,
        userAgent: true,
        expiresAt: true,
      },
    });

    if (!sessions || sessions.length === 0) {
      throw new NotFoundException(USER_ERRORS.SESSION_NOT_FOUND);
    }

    return sessions;
  }

  async deleteSession(userId: string, sessionId: string): Promise<void> {
    // Найти сессию по ID и userId
    const session = await this.prisma.session.findFirst({
      where: {
        id: sessionId,
        userId: userId,
      },
    });

    // Если сессия не найдена, выбросить исключение
    if (!session) {
      throw new NotFoundException(USER_ERRORS.SESSION_NOT_FOUND);
    }

    // Удалить сессию
    await this.prisma.session.delete({
      where: { id: sessionId },
    });

    // Логировать событие выхода
    await this.prisma.accessLog.create({
      data: {
        userId,
        eventType: LogEventType.LOGOUT, // Используем enum для события
      },
    });
  }

  async enable2FA(
    userId: string,
  ): Promise<{ otpauthUrl: string; qrCodeDataUrl: string }> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });
    if (!user) {
      throw new NotFoundException(USER_ERRORS.NOT_FOUND);
    }

    const secret = authenticator.generateSecret();
    const otpauthUrl = authenticator.keyuri(user.email, 'QUIZAPP', secret);
    const qrCodeDataUrl = await qrcode.toDataURL(otpauthUrl);

    await this.prisma.user.update({
      where: { id: userId },
      data: {
        twoFactorSecret: secret, // переименуй в Prisma и миграции
        twoFactorExpiresAt: new Date(Date.now() + 30 * 60 * 1000),
      },
    });

    return { otpauthUrl, qrCodeDataUrl };
  }

  async verify2FA(
    userId: string,
    dto: Verify2FADto,
  ): Promise<{ valid: boolean }> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user || !user.twoFactorSecret) {
      throw new NotFoundException(USER_ERRORS.NOT_FOUND);
    }

    if (
      user.twoFactorExpiresAt &&
      user.twoFactorExpiresAt.getTime() < Date.now()
    ) {
      throw new BadRequestException(
        'Срок действия 2FA-секрета истёк. Повторите активацию.',
      );
    }

    const isValid = authenticator.verify({
      token: dto.code,
      secret: user.twoFactorSecret,
    });

    if (!isValid) {
      throw new BadRequestException(USER_ERRORS.TWO_FA_INCORRECT);
    }

    await this.prisma.user.update({
      where: { id: userId },
      data: {
        twoFactorEnabled: true,
        twoFactorExpiresAt: null,
      },
    });

    return { valid: true };
  }

  async disable2FA(userId: string): Promise<void> {
    // Проверка существования пользователя
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });
    if (!user) {
      throw new NotFoundException(USER_ERRORS.NOT_FOUND);
    }

    // Проверка, включена ли двухфакторная аутентификация
    if (!user.twoFactorEnabled) {
      throw new ForbiddenException(USER_ERRORS.TWO_FA_NOT_ENABLED);
    }

    // Отключение 2FA
    await this.prisma.user.update({
      where: { id: userId },
      data: {
        twoFactorEnabled: false,
        twoFactorSecret: null,
        twoFactorExpiresAt: null,
      },
    });

    await this.prisma.accessLog.create({
      data: {
        userId,
        eventType: 'LOGOUT',
      },
    });
  }
}
