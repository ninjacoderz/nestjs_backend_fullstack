import { IsEmail, IsString, Matches, MinLength } from "class-validator";

export class LoginDto {

    @IsEmail()
    email: string;

    @IsString()
    @Matches(/^(?=.*[0-9])/, {message: "password must contain at least 1 number "})
    password: string;
}