import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { Request } from "express";
import { Observable } from "rxjs";

@Injectable()
export class AuthGuard implements CanActivate {
    constructor (private jwtService: JwtService){}
    canActivate(context: ExecutionContext): boolean | Promise<boolean> | Observable<boolean> {
        const request = context. switchToHttp().getRequest();
        const token = this.extractTokenFromheader(request);

        if(!token) {
            throw new UnauthorizedException('Invalid token');
        }

        try {
            const payload = this.jwtService.verify(token)
            request.userId = payload.userId;
        } catch (e) {
            throw new UnauthorizedException('Invalid token')
        }

        return true;
    }
    private extractTokenFromheader(request: Request) : string | undefined {
        return request.headers.authorization?.split(' ')[1];
    }
}       