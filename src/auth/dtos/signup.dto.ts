import { IsEmail, IsString, Matches, MinLength } from "class-validator";

export class SignupDto {
    @IsString()
    name: string;

    @IsEmail()
    email: string;

    @IsString()
    @MinLength(6)
    @Matches(/^(?=.*[0-9])/, {message: "password must contain at least 1 number "})
    password: string;
}