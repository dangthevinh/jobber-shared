import JWT from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';

const tokens: string[] = ['auth', 'seller', 'gig', 'search', 'buyer', 'message', 'order', 'review'];

export function verifyGatewayRequest(req: Request, res: Response, next: NextFunction): void {
    if (!req.headers?.gatewayToken) {
        throw new NotAuthorizeError('Invalid request', 'verifyGatewaRequest() method: Request not coming from api gateway');
    }
    const token: string = req.headers?.gatewayToken;
    if (!token) {
        throw new NotAuthorizeError('Invalid request', 'verifyGatewaRequest() method: Request not coming from api gateway');
    }
    try {
        const payload: { id: string; iat: number } = JWT.verify(token, '') as { id: string; iat: number };
        if (!tokens.includes(payload.id)) {
            throw new NotAuthorizeError('Invalid request', 'verifyGatewaRequest() method: Request not coming from api gateway');
        }
    } catch (error) {
        throw new NotAuthorizeError('Invalid request', 'verifyGatewaRequest() method: Request not coming from api gateway');
    }
}

