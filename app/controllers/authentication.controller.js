//importando encriptacion de datos sensibles
import bcryptjs from "bcryptjs";
import JsonWebToken from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();
//control de usuarios existentes
export const usuarios = [
  {
    user: "1",
    email: "1@1",
    password: "$2b$05$ZF2V.Yat.dUJOmPBUODdY.BeqERMsTf50wF2ZwYPOVhLT2BjS7kKu",
  },
];
//Funcion de login
async function login(req, res) {
  console.log(req.body);
  const user = req.body.user;
  const password = req.body.password;
  if (!user || !password) {
    return res
      .status(400)
      .send({ status: "Error", message: "los campos estan incompletos" });
  }
  const usuarioARevisar = usuarios.find((usuario) => usuario.user === user);
  if (!usuarioARevisar) {
    return res
      .status(400)
      .send({ status: "Error", message: "Error durante el login" });
  }
  const loginCorrecto = await bcryptjs.compare(
    password,
    usuarioARevisar.password
  );
  if (!loginCorrecto) {
    return res
      .status(400)
      .send({ status: "Error", message: "Error durante el login" });
  }

  //autenticacion de seguridad con token ENV
  const token = JsonWebToken.sign(
    { user: usuarioARevisar.user },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRATION }
  );

  const cookieOption = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000
    ),
    path: "/",
  };
  res.cookie("jwt", token, cookieOption);
  res.send({ status: "ok", message: "Usuario loggeado", redirect: "/admin" });
}
//Funcion de registro
async function register(req, res) {
  const user = req.body.user;
  const password = req.body.password;
  const email = req.body.email;
  if (!user || !password || !email) {
    return res
      .status(400)
      .send({ status: "Error", message: "los campos estan incompletos" });
  }
  const usuarioARevisar = usuarios.find((usuario) => usuario.user === user);
  if (usuarioARevisar) {
    return res
      .status(400)
      .send({ status: "Error", message: "Este usuario ya existe" });
  }
  const salt = await bcryptjs.genSalt(5);
  const hashPassword = await bcryptjs.hash(password, salt);
  const nuevoUsuario = {
    user,
    email,
    password: hashPassword,
  };
  usuarios.push(nuevoUsuario);
  console.log(usuarios);
  res.status(201).send({
    status: "ok",
    message: `usuario ${nuevoUsuario.user} agregado`,
    redirect: "/",
  });
}

export const methods = {
  login,
  register,
};
