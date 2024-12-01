import { Body, Controller, Post, Put, Req, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dtos/signup.dto';
import { LoginDto } from './dtos/login.dto';
import { RefreshTokenDto } from './dtos/refresh-token.dto';
import { ChangePasswordDto } from './dtos/change-password.dto';
import { AuthGuard } from '../guards/auth.guard';
import { ForgotPasswordDto } from './dtos/forgot-password.dto';
import { ResetPasswordDto } from './dtos/reset-password.dto';


@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // TODO: POST Signup
  @Post('signup') // auth/signup
  async signUp(@Body() signupData: SignupDto) {
    return this.authService.signup(signupData)
  }


  // TODO: POST Login
  @Post('login') 
  async login(@Body() credentials: LoginDto): Promise<{accessToken: string, refreshToken: string}> {
    return this.authService.login(credentials)
  }

  // TODO: POST Refresh Token
  @Post('refresh')
  async refreshTokens(@Body() refreshTokenDto: RefreshTokenDto) {
    return this.authService.refreshTokens(refreshTokenDto.refreshToken)
  }

  // TODO: Put Change password
  @Put('change-password')
  @UseGuards(AuthGuard)
  async changePassword(@Body() changePasswordDto: ChangePasswordDto, @Req() req) {
    return this.authService.changePassword(req.userId, changePasswordDto )
  }

  // TODO: Forgot password
  @Post("forgot-password")
  async forgotPassword (@Body() forgotPasswordDto: ForgotPasswordDto) {
    return this.authService.forgotPassword(forgotPasswordDto.email);
  }

  // TODO: Reset password
  // TODO: Forgot password
  @Put("reset-password")
  async resetPassword (@Body() resetPasswordDto: ResetPasswordDto) {
    return this.authService.resetPassword(resetPasswordDto.newPassword, resetPasswordDto.resetToken);
  }
}
