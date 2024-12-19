import { Request, Response, NextFunction } from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';
import dotenv from 'dotenv';
import { verify } from 'crypto';

dotenv.config();
const SECRET_KEY = process.env.SECRET_KEY;

if (!SECRET_KEY) {
    throw new Error("SECRET_KET is not defined in the .env file.");
}

export const authMiddleware = async (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers['authorization'];

    if (!authHeader) {
        throw new Error("Access denied, token not provided!");
    }

    const token = authHeader.split(' ')[1];

    if (!token) {
        throw new Error("Access denied, token not provided!");
    }

    try {
        const decoded = jwt.verify(token, SECRET_KEY) as JwtPayload;
        (req as any).user = decoded;
        next();
    } catch(error: any) {
        res.status(400).json(HttpResult.Fail("A unexpected error occured on authMiddleware"));
    }
}
