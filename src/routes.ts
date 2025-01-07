import { Router } from 'express';
import { authSession, changePassword, createUser, getUser } from './controller';

const routes = Router();

routes.post('/signIn', authSession);
routes.get('/signIn', getUser);
routes.post('/signUp', createUser);
routes.put('/resetPassword', changePassword);


export { routes };