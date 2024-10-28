// routes/user.js
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const auth = require("../middleware/auth");

const router = express.Router();

// Register new user
router.post("/register", async (req, res) => {
    const { username, password, role } = req.body;
    try {
        const user = new User({ username, password: await bcrypt.hash(password, 10), role });
        await user.save();
        res.json({ msg: "User registered" });
    } catch (error) {
        res.status(500).send("Server error");
    }
});

// Login user
router.post("/login", async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(400).json({ msg: "User does not exist" });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ msg: "Invalid credentials" });

        const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: "1h" });
        res.json({ token });
    } catch (error) {
        res.status(500).send("Server error");
    }
});

module.exports = router;
