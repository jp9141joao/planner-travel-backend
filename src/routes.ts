import { Router } from "express";
import { createUser, authSession, passwordUserReset } from './controller';
import { authMiddleware } from "./authMiddleware";

const routes = Router();

routes.put('/signUp', authMiddleware, createUser);
routes.post('/signIn', authMiddleware, authSession);
routes.put('/resetPassword', authMiddleware, passwordUserReset);

export { routes };