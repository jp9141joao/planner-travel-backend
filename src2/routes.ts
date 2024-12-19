import { Router } from 'express';
import { createProduto, getProdutos, createUsuario, createPedido, getPedidos, getUsuarios, autentica} from './controllers';
import { authMiddleware } from './authMiddleware';

const routes = Router();

routes.get('/produtos', authMiddleware, getProdutos);
routes.post('/produtos', authMiddleware, createProduto);
routes.get('/usuarios', authMiddleware, getUsuarios);
routes.post('/usuarios', authMiddleware, createUsuario);
routes.post('/usuarios/login', autentica);
routes.post('/pedidos', authMiddleware, createPedido);
routes.get('/pedidos', authMiddleware, getPedidos);

export { routes };