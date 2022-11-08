import {
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { hash, verify } from 'argon2';
import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto';
import { Tokens } from './types';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwtService: JwtService) {}

  async signUpLocal(dto: AuthDto): Promise<Tokens> {
    const hashedPassword = await this.hashData(dto.password);
    const newUser = await this.prisma.user.create({
      data: { email: dto.email, password: hashedPassword },
    });

    const tokens = await this.getTokens(newUser.id, newUser.email);
    await this.saveRtHash(newUser.id, tokens.refresh_token);
    return tokens;
  }

  async signInLocal(authDto: AuthDto): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: { email: authDto.email },
    });

    if (!user) {
      throw new UnauthorizedException();
    }

    const doesPasswordMatch = await this.verifyPassword(
      user.password,
      authDto.password,
    );

    if (!doesPasswordMatch) {
      throw new UnauthorizedException();
    }

    const tokens = await this.getTokens(user.id, user.email);
    await this.saveRtHash(user.id, tokens.refresh_token);

    return tokens;
  }

  async logOut(userId: number) {
    console.log(userId);
    await this.prisma.user.updateMany({
      where: {
        id: userId,
        refreshToken: {
          not: null,
        },
      },
      data: {
        refreshToken: null,
      },
    });
  }

  async refresh(userId: number, rt: string) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user || user.refreshToken) {
      throw new ForbiddenException('Access denied');
    }

    const doesRtMatch = await verify(user.refreshToken, rt);

    if (!doesRtMatch) {
      throw new ForbiddenException('Access denied');
    }

    const tokens = await this.getTokens(user.id, user.email);
    await this.saveRtHash(user.id, tokens.refresh_token);
    return tokens;
  }

  private hashData(data: string): Promise<string> {
    return hash(data);
  }

  private verifyPassword(hash, password): Promise<boolean> {
    return verify(hash, password);
  }

  private async getTokens(userId: number, email: string) {
    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          expiresIn: 60 * 15,
          secret: 'at-secret',
        },
      ),
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          expiresIn: 60 * 60 * 24 * 7,
          secret: 'rt-secret',
        },
      ),
    ]);

    return {
      access_token: at,
      refresh_token: rt,
    };
  }

  private async saveRtHash(userId: number, rt: string) {
    const hash = await this.hashData(rt);
    await this.prisma.user.update({
      where: { id: userId },
      data: { refreshToken: hash },
    });
  }
}
