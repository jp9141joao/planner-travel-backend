import { PrismaClient } from '@prisma/client';
import { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

const prisma = new PrismaClient();


const SECRET_KEY = 'hackathon'; 

export const getProdutos = async (req: Request, res: Response) => {
  const produtos = await prisma.tb_produto.findMany();
  res.json(produtos);
};

export const createProduto = async (req: Request, res: Response) => {
  const { descricao, nome, url_imagem, preco } = req.body;
  const produto = await prisma.tb_produto.create({
    data: { descricao, nome, url_imagem, preco },
  });
  res.json(produto);
};

export const getUsuarios = async (req: Request, res: Response) => {
    try {
      const usuarios = await prisma.tb_usuario.findMany();
      res.json(usuarios);
    } catch (error) {
      res.status(500).json({ error: 'Erro ao buscar usuários' });
    }
  };

export const createUsuario = async (req: Request, res: Response) => {
  const { email, nome, senha, telefone, data_aniversario } = req.body;
  // Gerar o hash da senha com um custo de 10 rounds
  const hashedPassword = await bcrypt.hash(senha, 10);

  const usuario = await prisma.tb_usuario.create({
    data: { 
      email, 
      nome, 
      senha: hashedPassword, 
      telefone, 
      data_aniversario },
  });
  res.json(usuario);
};

// Função de login
export const autentica = async (req: Request, res: Response): Promise<void> => {
  const { email, senha } = req.body;

  try {
    // Verificar se o usuário existe
    const usuario = await prisma.tb_usuario.findUnique({
      where: { email },
    });

    if (!usuario) {
       res.status(404).json({ error: 'Usuário não encontrado' });
       return
    }

    // Comparar a senha fornecida com o hash armazenado no banco de dados
    const senhaValida = await bcrypt.compare(senha, usuario.senha);

    if (!senhaValida) {
      res.status(401).json({ error: 'Senha incorreta' });
      return
    }

     // Login bem-sucedido: Gerar um token JWT
     const token = jwt.sign(
      { id: usuario.id, email: usuario.email }, // Dados para incluir no token
      SECRET_KEY, // Chave secreta
      { expiresIn: '1h' } // Duração do token
    );

    
    res.status(200).json({ message: 'Login bem-sucedido', token });

  } catch (error) {
    // Erro ao processar a requisição
    console.error(error);
    res.status(500).json({ error: 'Erro ao fazer login' });
  }
};

export const createPedido = async (req: Request, res: Response) => {
    const { id_usuario, status, data, itens } = req.body;
  
    try {
      // Criar o pedido
      const pedido = await prisma.tb_pedido.create({
        data: {
          id_usuario,
          status,
          data,
          itens: {
            create: itens.map((item: any) => ({
              id_produto: item.id_produto,
              qtde: item.qtde,
              preco: item.preco
            }))
          }
        },
        include: {
          itens: true
        }
      });
  
      res.json(pedido);
    } catch (error) {
      res.status(500).json({ error: 'Erro ao criar pedido' });
    }
  };

export const getPedidos = async (req: Request, res: Response) => {
  const pedidos = await prisma.tb_pedido.findMany({
    include: { itens: true },
  });
  res.json(pedidos);
};