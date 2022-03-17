import express from 'express';
import { v4 } from 'uuid';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import * as yup from 'yup';

dotenv.config();
const app = express();
app.use(express.json());

const config = {
  secret: process.env.SECRET_KEY,
  expiresIn: '1h',
};

const usersDB = [];

//  YuP Shapes

const userSchema = yup.object().shape({
  uuid: yup.string().default(() => v4()),
  username: yup.string().required(),
  age: yup.number().required().positive().integer(),
  email: yup.string().email().required(),
  password: yup.string().required(),
  createOn: yup.date().default(() => new Date()),
});

const loginSchema = yup.object().shape({
  username: yup.string().required(),
  password: yup.string().required(),
});

const passwordSchema = yup.object().shape({
  password: yup.string().required(),
});

// Middlewares
const validateSchema = (schema) => async (req, res, next) => {
  try {
    const dataValid = await schema.validate(req.body, {
      abortEarly: false,
      stripUnknow: true,
    });
    req.validated = dataValid;

    return next();
  } catch (err) {
    return res.status(422).json({ error: `${err.errors}` });
  }
};

// eslint-disable-next-line consistent-return
const validateUserOn = (req, res, next) => {
  try {
    const token = req.headers.authorization.split(' ')[1];
    jwt.verify(token, config.secret, (err, decode) => {
      if (err) {
        return res.status(401).json({ error: 'no token authorization' });
      }
      if (usersDB.find((user) => user.password === decode.password)) {
        req.userOn = usersDB.find((user) => user.password === decode.password);
        return next();
      }
      return res.status(403).json({ message: 'you are not allowed' });
    });
  } catch (error) {
    return res.status(401).json({ message: 'needs authentication' });
  }
};

// Routes
app.post('/signup', validateSchema(userSchema), async (req, res) => {
  try {
    const { validated } = req;
    const passwordHash = await bcrypt.hash(req.body.password, 10);
    validated.password = passwordHash;
    usersDB.push(validated);

    return res.status(201).json({
      uuid: validated.uuid,
      username: validated.username,
      email: validated.email,
      age: validated.age,
      createOn: validated.createOn,
    });
  } catch (err) {
    return res.status(404).json({ error: `${err}` });
  }
});

app.post('/login', validateSchema(loginSchema), async (req, res) => {
  try {
    const { validated } = req;
    const user = usersDB.find((use) => use.username === validated.username);
    const match = await bcrypt.compare(validated.password, user.password);

    const token = jwt.sign(
      { username: validated.username, password: user.password },
      config.secret,
      { expiresIn: config.expiresIn },
    );

    if (match) {
      return res.json({ token: `${token}` });
    }
    return res.status(404).json({ message: 'password invalid.' });
  } catch (err) {
    return res.status(400).json({
      message: 'username invalid',
    });
  }
});

// eslint-disable-next-line consistent-return
app.get('/users', validateUserOn, (req, res) => {
  if (req.userOn) {
    return res.json(usersDB);
  }
});

app.put(
  '/users/:uuid/password',
  validateUserOn,
  validateSchema(passwordSchema),
  async (req, res) => {
    try {
      const { uuid } = req.params;
      const { validated } = req;
      const passwordHash = await bcrypt.hash(validated.password, 10);
      const userFound = usersDB.find((user) => user.uuid === uuid);
      if (!userFound) {
        return res
          .status(403)
          .json({ message: 'without authorization for this action' });
      }
      userFound.password = passwordHash;
      return res.status(204).json();
    } catch (err) {
      return res.status(404).json({ error: `${err.errors}` });
    }
  },
);

app.listen(3000);
