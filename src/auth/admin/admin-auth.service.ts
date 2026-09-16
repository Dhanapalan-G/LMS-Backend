import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { randomInt } from 'crypto';

import { PrismaService } from '../../prisma/prisma.service';
import { TokenService } from '../../auth/token.service';

import { AdminLoginDto } from './dto/admin-login.dto';
import { AdminVerifyOtpDto } from './dto/admin-verify-otp.dto';
import { AdminForgotPasswordDto } from './dto/admin-forgot-password.dto';
import {
  AdminStatus,
  OtpChannel,
  OtpPurpose,
} from '../../generated/prisma/client';
import { SmsService } from '../../notifications/sms/sms.service';
import { EmailService } from '../../notifications/email/email.service';
import { AdminResetPasswordDto } from './dto/admin-reset-password.dto';
import { AdminPasswordVerifyOtpDto } from './dto/admin-password-verify-otp.dto';

@Injectable()
export class AdminAuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly tokenService: TokenService,
    private readonly smsService: SmsService,
    private readonly emailService: EmailService,
  ) {}

  async login(dto: AdminLoginDto) {
    const admin = await this.prisma.adminUser.findUnique({
      where: {
        employeeId: dto.employeeId,
      },
    });

    if (!admin) {
      throw new UnauthorizedException('Invalid Employee Id or password');
    }

    if (admin.status !== 'ACTIVE') {
      throw new UnauthorizedException(
        `Admin account is ${admin.status.toLowerCase()}`,
      );
    }

    const passwordValid = await bcrypt.compare(dto.password, admin.password);

    if (!passwordValid) {
      throw new UnauthorizedException('Invalid Employee Id or password');
    }

    const otp = randomInt(100000, 1000000).toString();

    const codeHash = await bcrypt.hash(otp, 10);

    const expiresAt = new Date(Date.now() + 20 * 60 * 1000);

    await this.prisma.adminOtpVerification.create({
      data: {
        adminUserId: admin.id,
        codeHash,
        purpose: 'LOGIN',
        channel: 'SMS',
        expiresAt,
        lastSentAt: new Date(),
      },
    });

    return {
      message: 'OTP sent successfully',
      adminUserId: admin.id,

      // Development only
      otp,
    };
  }

  async verifyOtp(dto: AdminVerifyOtpDto) {
    const admin = await this.prisma.adminUser.findUnique({
      where: {
        employeeId: dto.employeeId,
      },
    });

    if (!admin) {
      throw new UnauthorizedException('Invalid OTP');
    }
    const otpRecord = await this.prisma.adminOtpVerification.findFirst({
      where: {
        adminUserId: admin.id,
        purpose: 'LOGIN',
        verifiedAt: null,
        revokedAt: null,
        expiresAt: {
          gt: new Date(),
        },
      },
      orderBy: {
        createdAt: 'desc',
      },
    });
    if (!otpRecord) {
      throw new UnauthorizedException('OTP expired or invalid');
    }

    if (otpRecord.attempts >= otpRecord.maxAttempts) {
      throw new UnauthorizedException('Maximum OTP attempts exceeded');
    }

    const valid = await bcrypt.compare(dto.otp, otpRecord.codeHash);

    if (!valid) {
      await this.prisma.adminOtpVerification.update({
        where: {
          id: otpRecord.id,
        },
        data: {
          attempts: {
            increment: 1,
          },
        },
      });

      throw new UnauthorizedException('Invalid OTP');
    }
    await this.prisma.adminOtpVerification.update({
      where: {
        id: otpRecord.id,
      },
      data: {
        verifiedAt: new Date(),
      },
    });

    return this.issueTokens(admin);
  }

  private async issueTokens(admin: any) {
    const payload = {
      sub: admin.id,
      authType: 'ADMIN' as const,
      schoolId: admin.schoolId,
      role: admin.role,
    };

    const accessToken = await this.tokenService.generateAccessToken(payload);
    const refreshToken = await this.tokenService.generateRefreshToken(payload);
    const tokenHash = this.tokenService.hashRefreshToken(refreshToken);
    await this.prisma.adminRefreshToken.create({
      data: {
        adminUserId: admin.id,
        tokenHash,
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
      },
    });

    return {
      message: 'Login successful',
      accessToken,
      refreshToken,
      admin: {
        id: admin.id,
        name: admin.name,
        employeeId: admin.employeeId,
        email: admin.email,
        role: admin.role,
        schoolId: admin.schoolId,
      },
    };
  }

  async refresh(refreshToken: string) {
    let payload: any;

    try {
      payload = await this.tokenService.verifyRefreshToken(refreshToken);
    } catch {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    const tokenHash = this.tokenService.hashRefreshToken(refreshToken);

    const storedToken = await this.prisma.adminRefreshToken.findFirst({
      where: {
        tokenHash,
        revokedAt: null,
        expiresAt: {
          gt: new Date(),
        },
      },
    });

    if (!storedToken) {
      throw new UnauthorizedException('Refresh token is invalid or revoked');
    }

    const admin = await this.prisma.adminUser.findUnique({
      where: {
        id: payload.sub,
      },
    });

    if (!admin || admin.status !== 'ACTIVE') {
      throw new UnauthorizedException('Admin account is not active');
    }

    // Rotate old refresh token
    await this.prisma.adminRefreshToken.update({
      where: {
        id: storedToken.id,
      },
      data: {
        revokedAt: new Date(),
      },
    });

    return this.issueTokens(admin);
  }

  async forgotPassword(dto: AdminForgotPasswordDto) {
    const admin = await this.prisma.adminUser.findFirst({
      where: {
        OR: [
          { employeeId: dto.identifier },
          { email: dto.identifier },
          { phone: dto.identifier },
        ],
      },
    });

    if (!admin) {
      throw new NotFoundException(
        'No admin found with this employee id or email or phone number',
      );
    }

    if (admin.status !== AdminStatus.ACTIVE) {
      throw new UnauthorizedException('Admin account is not active');
    }
    let channel: OtpChannel;

    if (admin.employeeId === dto.identifier) {
      channel = OtpChannel.EMAIL;
      channel = OtpChannel.SMS;
    } else if (admin.email === dto.identifier) {
      channel = OtpChannel.EMAIL;
    } else {
      channel = OtpChannel.SMS;
    }
    const latestOtp = await this.prisma.adminOtpVerification.findFirst({
      where: {
        adminUserId: admin.id,
        purpose: OtpPurpose.PASSWORD_RESET,
        channel,
      },
      orderBy: {
        createdAt: 'desc',
      },
    });

    // 60 second resend restriction
    if (latestOtp && Date.now() - latestOtp.lastSentAt.getTime() < 60 * 1000) {
      throw new BadRequestException(
        'Please wait 60 seconds before requesting another OTP',
      );
    }

    // Invalidate previous OTPs
    await this.prisma.adminOtpVerification.updateMany({
      where: {
        adminUserId: admin.id,
        purpose: OtpPurpose.PASSWORD_RESET,
        verifiedAt: null,
      },
      data: {
        verifiedAt: new Date(),
      },
    });

    // Generate OTP
    const otp = randomInt(100000, 1000000).toString();

    // Hash OTP
    const codeHash = await bcrypt.hash(otp, 10);

    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    await this.prisma.adminOtpVerification.create({
      data: {
        adminUserId: admin.id,
        codeHash,
        purpose: OtpPurpose.PASSWORD_RESET,
        channel,
        expiresAt,
        lastSentAt: new Date(),
      },
    });

    // Send OTP
    if (channel === OtpChannel.EMAIL) {
      await this.emailService.sendOtp(admin.email, otp);
    } else {
      await this.smsService.sendOtp(admin.phone!, otp);
    }

    return {
      message: `OTP sent successfully to your ${channel === OtpChannel.EMAIL ? 'email' : 'phone number'}`,
      otp,
      channel,
      admin,
    };
  }

  async verifyPasswordOtp(dto: AdminPasswordVerifyOtpDto) {
    const admin = await this.prisma.adminUser.findUnique({
      where: {
        employeeId: dto.employeeId,
      },
    });

    if (!admin) {
      throw new NotFoundException('Admin not found');
    }

    const otpRecord = await this.prisma.adminOtpVerification.findFirst({
      where: {
        adminUserId: admin.id,
        purpose: OtpPurpose.PASSWORD_RESET,
        verifiedAt: null,
      },
      orderBy: {
        createdAt: 'desc',
      },
    });

    if (!otpRecord) {
      throw new BadRequestException('OTP not found or already used');
    }

    if (otpRecord.expiresAt < new Date()) {
      throw new BadRequestException('OTP has expired');
    }

    if (otpRecord.attempts >= 5) {
      throw new BadRequestException('Maximum OTP attempts exceeded');
    }

    const isValid = await bcrypt.compare(dto.otp, otpRecord.codeHash);

    if (!isValid) {
      await this.prisma.adminOtpVerification.update({
        where: {
          id: otpRecord.id,
        },
        data: {
          attempts: {
            increment: 1,
          },
        },
      });

      throw new BadRequestException('Invalid OTP');
    }

    await this.prisma.adminOtpVerification.update({
      where: {
        id: otpRecord.id,
      },
      data: {
        verifiedAt: new Date(),
      },
    });

    const resetToken = await this.tokenService.generateAdminPasswordResetToken(
      admin.id,
    );

    return {
      message: 'OTP verified successfully',
      resetToken,
    };
  }

  async resetPassword(dto: AdminResetPasswordDto) {
    const payload = await this.tokenService.verifyAdminPasswordResetToken(
      dto.resetToken,
    );

    if (payload.authType !== 'ADMIN' || payload.purpose !== 'PASSWORD_RESET') {
      throw new UnauthorizedException('Invalid password reset token');
    }

    const admin = await this.prisma.adminUser.findUnique({
      where: {
        id: payload.sub,
      },
    });

    if (!admin) {
      throw new NotFoundException('Admin not found');
    }

    const hashedPassword = await bcrypt.hash(dto.newPassword, 10);

    await this.prisma.$transaction([
      this.prisma.adminUser.update({
        where: {
          id: admin.id,
        },
        data: {
          password: hashedPassword,
        },
      }),

      this.prisma.adminRefreshToken.updateMany({
        where: {
          adminUserId: admin.id,
          revokedAt: null,
        },
        data: {
          revokedAt: new Date(),
        },
      }),
    ]);

    return {
      message: 'Password reset successfully',
    };
  }

  async logout(refreshToken: string) {
    const tokenHash = this.tokenService.hashRefreshToken(refreshToken);

    await this.prisma.adminRefreshToken.updateMany({
      where: {
        tokenHash,
        revokedAt: null,
      },
      data: {
        revokedAt: new Date(),
      },
    });

    return {
      message: 'Logged out successfully',
    };
  }

  async logoutAll(adminUserId: string) {
    await this.prisma.adminRefreshToken.updateMany({
      where: {
        adminUserId,
        revokedAt: null,
      },
      data: {
        revokedAt: new Date(),
      },
    });

    return {
      message: 'Logged out from all devices successfully',
    };
  }
}
