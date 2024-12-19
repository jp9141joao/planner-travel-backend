import { Request, Response, NextFunction } from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';

const SECRET_KEY = 'hackathon'; // Substitua pela sua chave secreta real

export const authMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  console.log(`entrou`)
  const authHeader = req.headers['authorization'];

  if (!authHeader) {
    res.status(401).json({ error: 'Acesso negado. Token não fornecido.' });
    return;
  }

  const token = authHeader.split(' ')[1]; // Supondo que o formato seja "Bearer <token>"

  if (!token) {
    res.status(401).json({ error: 'Acesso negado. Token não fornecido.' });
    return;
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY) as JwtPayload;
   // req.user = decoded; // Armazena o token decodificado em req.user
    next();
  } catch (error) {
    res.status(403).json({ error: 'Token inválido.' });
  }
};
