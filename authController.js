const userModel = require("../models/userModel")
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken')

// ------------------------- Register Controller
const registerController = async (req, res) => {
    try {
        const existingUser = await userModel.findOne({
            email: req.body.email
        })

        // validation
        if (existingUser) {
            return res.status(200).send({
                message: 'User already Registered',
                success: false
            })
        }

        // Hashing the password (Hash password)
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(req.body.password, salt);
        req.body.password = hashedPassword;

        // rest data
        const user = new userModel(req.body);
        await user.save();
        return res.status(201).send({
            message: 'User created',
            success: true,
            user
        })
    } catch (error) {
        console.log(`Error in Registration : ${error}`)
        res.status(500).send({
            message: 'Error in Registration',
            success: false,
            error
        })
    }
}


// --------------------------------- login controller
const loginController = async (req, res) => {
    try {
        const user = await userModel.findOne({ email: req.body.email })
        if (!user) {
            return res.status(404).send({
                message: 'Invalid user',
                success: false
            })
        }
        //check role
        if (user.role != req.body.role) {
            return res.status(500).send({
                message: 'role did not match',
                success: false
            })
        }
        // compare password
        const comparePassword = await bcrypt.compare(req.body.password, user.password);
        if (!comparePassword) {
            return res.status(500).send({
                message: 'Invalid Password',
                success: false
            })
        }

        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" })
        return res.status(200).send({
            message: 'Login Successfull',
            success: true,
            token,
            user
        })

    } catch (error) {
        console.log(`Error in login: ${error}`)
        res.status(500).send({
            message: 'Error in login',
            success: false
        })
    }
}

// Get current user
const currentUserController = async (req, res) => {
    try {
        const user = await userModel.findOne({ _id: req.body.userId })
        return res.status(200).send({
            message: 'User Fetched Successfully',
            success: true,
            user
        })
    } catch (error) {
        console.log(`Unable to get current user : ${error}`);
        res.status(500).send({
            message: 'Unable to get current user',
            success: false,
            error
        })
    }
}

module.exports = { registerController, loginController, currentUserController }