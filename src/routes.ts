import { Router } from 'express';
import { authSession, changePassword, createUser } from './controller';

const routes = Router();

routes.post('/signIn', authSession);
routes.post('/signUp', createUser);
routes.put('/resetPassword', changePassword);

export { routes };