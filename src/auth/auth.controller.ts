import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { Tokens } from './types';
import { GetCurrentUser, Public } from '../common/decorators';
import { RtGuard } from '../common/guards';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Public()
  @Post('local/signup')
  @HttpCode(HttpStatus.CREATED)
  signUpLocal(@Body() authDto: AuthDto): Promise<Tokens> {
    return this.authService.signUpLocal(authDto);
  }

  @Public()
  @Post('local/signin')
  @HttpCode(HttpStatus.OK)
  signInLocal(@Body() authDto: AuthDto) {
    return this.authService.signInLocal(authDto);
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  logOut(@GetCurrentUser('sub') userId: number) {
    return this.authService.logOut(userId);
  }

  @Public()
  @UseGuards(RtGuard)
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  refresh(
    @GetCurrentUser('sub') id: number,
    @GetCurrentUser('refreshToken') refreshToken: string,
  ) {
    return this.authService.refresh(id, refreshToken);
  }
}
