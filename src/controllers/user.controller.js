const catchError = require('../utils/catchError');
const User = require('../models/User');
const bcrypt = require('bcrypt');
const { sendEmail } = require('../utils/sendEmail');
const EmailCode = require('../models/EmailCode');
const jwt = require('jsonwebtoken');

const findAll = catchError(async(req, res) => {
    const users = await User.findAll();
    return res.json(users);
});

const create = catchError(async(req, res) => {
    const {email, password, firstName, frontBaseUrl} = req.body;
    const hashPass = await bcrypt.hash(password, 12);
    const newBody = {...req.body, password: hashPass};
    const newUser = await User.create(newBody);

    // generar codigo de verificacion de email
    const code = require('crypto').randomBytes(64).toString('hex');

    // guardar emailcode
    await EmailCode.create({
        code,
        userId: newUser.id
    });

    // envio de email
    sendEmail({
        to: email,
        subject: "Account verification",
        html:
            `<div style="max-width: 500px; margin: 50px auto; background-color: #f8fafc; padding: 30px; border-radius: 10px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1); font-family: 'Arial', sans-serif; color: #333333;">
      
                <h1 style="color: #007BFF; font-size: 28px; text-align: center; margin-bottom: 20px;">¡Hola ${firstName.toUpperCase()} ￼!</h1>    
            
                <p style="font-size: 18px; line-height: 1.6; margin-bottom: 25px; text-align: center;">Gracias por registrarte en nuestra aplicación. Para verificar su cuenta, haga clic en el siguiente enlace:</p>
            
                <div style="text-align: center;">
                <a href="${frontBaseUrl}/verify_email/${code}" style="display: inline-block; background-color: #007BFF; color: #ffffff; text-align:    
                center; padding: 14px 28px; border-radius: 6px; text-decoration: none; font-weight: bold; font-size: 18px;">¡Verificar cuenta!</a>
                </div>
            </div>`
    });
    return res.status(201).json(newUser);
});

const findOne = catchError(async(req, res) => {
    const { id } = req.params;
    const user = await User.findByPk(id);
    if(!user) return res.sendStatus(404);
    return res.json(user);
});

const remove = catchError(async(req, res) => {
    const { id } = req.params;
    const user = await User.findByPk(id);
     if(!user) return res.sendStatus(404);
    await user.destroy();
    return res.sendStatus(204);
});

const update = catchError(async(req, res) => {
    const { id } = req.params;
    const fieldsToDelete = ['email', 'password', 'isVerified'];
    fieldsToDelete.forEach(field => {
        delete req.body[field];
    })

    const user = await User.findByPk(id);
    if(!user) return res.sendStatus(404);
    const updatedUser = await user.update(req.body);
    return res.json(updatedUser);
});

const verifyUser = catchError(async(req, res) => {
    const {code} = req.params;
    const userCode = await EmailCode.findOne({where: {code}});
    if(!userCode) return res.sendStatus(404).json({error: 'User not found'});

    const user = await User.findByPk(userCode.userId);

    await user.update({
        isVerified: true
    });

    await userCode.destroy();

    return res.json(user);
});

const login = catchError(async(req, res) => {
    const {email, password} = req.body;
    const user = await User.findOne({where: {email}});
    
    if(!user) return res.sendStatus(401);

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if(!isPasswordValid) return res.sendStatus(401);

    const token = jwt.sign(
        {user},
        process.env.SECRET_TOKEN,
        {expiresIn: "1d"}
    );

    return res.json({user, token});
});

const logged = catchError(async(req, res) => {
    const user = req.user;
    return res.json(user);
});

const resetPassword = catchError(async(req, res) => {
    const {email, frontBaseUrl} = req.body;
    const user = await User.findOne({where:{email}});
    if(!user) return res.sendStatus(401).json({error: "User not found"});

    const code = require('crypto').randomBytes(64).toString('hex');
    
    await EmailCode.create({
        code,
        userId: user.id
    });

    sendEmail({
        to: email,
        subject: "Password reset",
        html:
            `<div style="max-width: 500px; margin: 50px auto; background-color: #f8fafc; padding: 30px; border-radius: 10px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1); font-family: 'Arial', sans-serif; color: #333333;">
      
                <h1 style="color: #007BFF; font-size: 28px; text-align: center; margin-bottom: 20px;">¡Hola ${user.firstName.toUpperCase()} ￼!</h1>    
            
                <p style="font-size: 18px; line-height: 1.6; margin-bottom: 25px; text-align: center;">Para resetear su contraseña, haga clic en el siguiente enlace:</p>
            
                <div style="text-align: center;">
                    <a href="${frontBaseUrl}/reset_password/${code}" style="display: inline-block; background-color: #007BFF; color: #ffffff; text-align: center; padding: 14px 28px; border-radius: 6px; text-decoration: none; font-weight: bold; font-size: 18px;">¡Resetear contraseña!</a>
                </div>
            </div>`
    });

    return res.json(user);
});

const updatePassword = catchError(async(req, res) => {
    const {code} = req.params;
    const {password} = req.body;

    const emailCode = await EmailCode.findOne({where: {code}});
    if(!emailCode) return res.sendStatus(404).json({error: "Code not found"});

    const user = await User.findByPk(emailCode.userId);

    const hashPassword = await bcrypt.hash(password, 12);
    const updatedUser = await user.update({password: hashPassword});

    await emailCode.destroy();

    return res.json(updatedUser);
});

module.exports = {
    findAll,
    create,
    findOne,
    remove,
    update,
    verifyUser,
    login,
    logged,
    resetPassword,
    updatePassword
}