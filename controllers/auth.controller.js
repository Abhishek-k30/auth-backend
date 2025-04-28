import User from "../models/user.model.js";
import bcrypt from "bcrypt";
import generateJWTTokenAndSetCookie from "../utils/generateToken.js";

const signup = async (req, res) => {
    try {
        const { name, email, phoneNumber, username, password } = req.body;

        // Check if any required field is missing
        if (!name || !email || !phoneNumber || !username || !password) {
            return res.status(400).json({ message: "All fields are required" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        // Check if username, email or phone number already exists
        const existingUser = await User.findOne({
            $or: [
                { username },
                { email },
                { phoneNumber }
            ]
        });

        if (existingUser) {
            if (existingUser.username === username) {
                return res.status(400).json({ message: "Username already exists" });
            }
            if (existingUser.email === email) {
                return res.status(400).json({ message: "Email already exists" });
            }
            if (existingUser.phoneNumber === phoneNumber) {
                return res.status(400).json({ message: "Phone number already exists" });
            }
        }

        const user = new User({
            name,
            email,
            phoneNumber,
            username,
            password: hashedPassword
        });

        generateJWTTokenAndSetCookie(user._id, res);
        await user.save();
        return res.status(201).json({
            _id: user._id,
            name: user.name,
            username: user.username
        });

    } catch (error) {
        console.log(error);
        return res.status(500).json({ message: "User registration failed!" });
    }
}

export const login = async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ message: "Username and password are required" });
        }

        const foundUser = await User.findOne({ username });
        if (!foundUser) {
            return res.status(401).json({ message: "Invalid username or password" });
        }

        const passwordMatch = await bcrypt.compare(password, foundUser?.password);
        if (!passwordMatch) {
            return res.status(401).json({ message: "Invalid username or password" });
        }

        generateJWTTokenAndSetCookie(foundUser._id, res);
        return res.status(200).json({
            _id: foundUser._id,
            name: foundUser.name,
            username: foundUser.username
        });

    } catch (error) {
        console.log(error);
        return res.status(500).json({ message: "Login failed!" });
    }
}

export default signup;