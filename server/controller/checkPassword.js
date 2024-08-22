const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const UserModel = require("../models/UserModel");

async function checkPassword(request, response) {
    try {
        const { password, userId } = request.body;
        const user = await UserModel.findById(userId);

        if (!user) {
            return response.status(400).json({
                message: "User not found",
                error: true,
            });
        }

        const verifyPassword = await bcryptjs.compare(password, user.password);

        if (!verifyPassword) {
            return response.status(400).json({
                message: "Incorrect password",
                error: true,
            });
        }

        const tokenData = {
            id: user._id,
            email: user.email,
        };
        const token = jwt.sign(tokenData, process.env.JWT_SECRET, { expiresIn: '1d' });

        const cookieOptions = {
            httpOnly: true,
            secure: true,
            sameSite: 'None',
        };

        return response.cookie('token', token, cookieOptions).status(200).json({
            message: "Login successfully",
            token: token,
            success: true,
        });

    } catch (error) {
        return response.status(500).json({
            message: error.message || error,
            error: true,
        });
    }
}

module.exports = checkPassword;
