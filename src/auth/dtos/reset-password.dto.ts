import { IsString, MinLength } from "class-validator";

export class ResetPasswordDto {

    @IsString()
    newPassword: string;

    @IsString()
    @MinLength(6)
    resetToken: string;
}