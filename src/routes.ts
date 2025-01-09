import { Router } from 'express';
import { authSession, changePassword, createUser, getUser, updateUser } from './controller';

const routes = Router();

routes.post('/signIn', authSession);
routes.get('/signIn', getUser);
routes.post('/signUp', createUser);
routes.put('/resetPassword', changePassword);
routes.put('/profileSettings', updateUser);


export { routes };