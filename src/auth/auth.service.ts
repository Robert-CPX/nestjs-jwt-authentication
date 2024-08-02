import { ForbiddenException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { PrismaClient } from '@prisma/client';
import { JwtPayload, Tokens } from './types';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaClient,
    private jwtService: JwtService,
    private config: ConfigService,
  ) {}

  async signupLocal(dto: AuthDto): Promise<Tokens> {
    const hash = await argon.hash(dto.password);
    const user = await this.prisma.user
      .create({
        data: {
          email: dto.email,
          hash,
        },
      })
      .catch((error) => {
        if (error instanceof PrismaClientKnownRequestError) {
          if (error.code === 'P2002') {
            throw new ForbiddenException('User already exists');
          }
        }
        throw error;
      });
    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);
    return tokens;
  }

  async signinLocal(dto: AuthDto): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });
    if (!user) {
      throw new ForbiddenException('Invalid credentials');
    }

    const passwordMatch = await argon.verify(user.hash, dto.password);
    if (!passwordMatch) {
      throw new ForbiddenException('Invalid credentials');
    }

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);

    return tokens;
  }

  async logout(userId: number): Promise<boolean> {
    await this.prisma.user.updateMany({
      where: { id: userId, hashedRt: { not: null } },
      data: { hashedRt: null },
    });
    return true;
  }

  async refreshTokens(userId: number, refreshToken: string): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });
    if (!user || !user.hashedRt) {
      throw new ForbiddenException('Access Denied');
    }
    const rtMatch = await argon.verify(user.hashedRt, refreshToken);
    if (!rtMatch) {
      throw new ForbiddenException('Access Denied');
    }

    const tokens = await this.getTokens(userId, user.email);
    await this.updateRtHash(userId, tokens.refresh_token);

    return tokens;
  }

  async updateRtHash(userId: number, refreshToken: string): Promise<void> {
    const hash = await argon.hash(refreshToken);
    await this.prisma.user.update({
      where: { id: userId },
      data: { hashedRt: hash },
    });
  }

  async getTokens(userId: number, email: string): Promise<Tokens> {
    const jwtPayload: JwtPayload = { sub: userId, email: email };
    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(jwtPayload, {
        secret: this.config.get<string>('AT_SECRET'),
        expiresIn: '15m',
      }),
      this.jwtService.signAsync(jwtPayload, {
        secret: this.config.get<string>('RT_SECRET'),
        expiresIn: '7d',
      }),
    ]);
    return { access_token: at, refresh_token: rt };
  }
}
