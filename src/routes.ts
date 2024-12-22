import { Router } from 'express';
import { createProduto, getProdutos, createUsuario, createPedido, getPedidos, getUsuarios, autentica} from './controllers';
import { authMiddleware } from './authMiddleware';
import { authSession, changePassword, createUser } from './controller';

const routes = Router();

routes.post('/signIn', authMiddleware, authSession);
routes.post('/signUp', authMiddleware, createUser);
routes.put('/resetPassword', authMiddleware, changePassword);

export { routes };