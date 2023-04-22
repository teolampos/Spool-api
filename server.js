const express = require("express");
const { MongoClient } = require("mongodb");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const cloudinary = require("cloudinary");

const server = express();

//We connect to the MongoDB database
let db;
MongoClient.connect(process.env.MONGO_URI)
  .then((client) => {
    db = client.db();
    server.listen(5000, () =>
      console.log("Server started listening on port 5000...")
    );
  })
  .catch((err) => {
    console.log(err);
  });

//CONFIGURING CLOUDINARY
cloudinary.config({
  cloud_name: process.env.REACT_APP_CLOUD_NAME,
  api_key: process.env.REACT_APP_API_KEY,
  api_secret: process.env.REACT_APP_API_SECRET,
});

server.use(express.json());
server.use(cookieParser());
//Implementing CORS
server.use(
  cors({
    origin: "http://localhost:3000",
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  })
);

server.post("/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    //CHECKS IF A USER WITH THE EXACT USERNAME IS ALREADY REGISTERED
    const sameUser = await db.collection("users").findOne({ username });
    if (sameUser != null) {
      return res
        .status(400)
        .json({ success: false, msg: "Username already exists" });
    }

    //HASHING USER PASSWORD
    let salt = await bcrypt.genSalt();
    let hashedPassword = await bcrypt.hash(password, salt);
    let user = {
      username,
      email,
      password: hashedPassword,
      profile: null,
      social: [],
    };
    await db.collection("users").insertOne(user);
    user = { username, email };
    const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET);
    res.cookie("ACCESS", token, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
    });

    res.status(201).json({ success: true, msg: "User added", user });
  } catch (err) {
    res.status(500).json({ success: false, msg: err });
  }
});

server.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    let user = await db.collection("users").findOne({ username });
    if (user == null) {
      return res.status(404).json({ success: false, msg: "No such user" });
    }
    if (await bcrypt.compare(password, user.password)) {
      let token = await jwt.sign(
        {
          username: user.username,
          email: user.email,
          profile: user.profile.url,
        },
        process.env.ACCESS_TOKEN_SECRET
      );
      res.cookie("ACCESS", token, {
        httpOnly: true,
        secure: true,
        sameSite: "lax",
      });
      res
        .status(200)
        .json({ success: true, username: user.username, email: user.email });
    } else {
      res.status(403).json({ success: false, msg: "Wrong password" });
    }
  } catch (err) {
    res.status(500).json({ success: false, msg: "Internal Server Error" });
  }
});

server.get("/auth", (req, res) => {
  const { ACCESS } = req.cookies;
  if (ACCESS) {
    jwt.verify(ACCESS, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
      if (err) res.status(403).json({ success: false, msg: "Unauthorized" });
      res.status(200).json({ success: true, user });
    });
  } else res.status(403).json({ success: false, msg: "Unauthorized" });
});

server.get("/platforms", async (req, res) => {
  try {
    let platforms = [];
    await db
      .collection("platforms")
      .find()
      .sort({ name: 1 })
      .forEach((platform) => platforms.push(platform));
    res.status(200).json({ success: true, platforms });
  } catch (err) {
    res.status(500).json({ msg: err });
  }
});

server.get("/users/:username", async (req, res) => {
  try {
    let platforms = [];
    let user = await db
      .collection("users")
      .findOne({ username: req.params.username });
    if (user == null) return res.status(404).json({ success: false });
    await db
      .collection("platforms")
      .find()
      .forEach((social) => platforms.push(social));
    res.status(200).json({
      empty: user.social.length == 0 ? true : false,
      socials: user.social,
      profile: user.profile,
      platforms,
    });
  } catch (err) {
    res.status(500).json({ success: false });
  }
});

server.put("/add", async (req, res) => {
  try {
    const { socialUrl, socialName, username } = req.body;
    const result = await db.collection("users").updateOne(
      { username },
      {
        $push: {
          social: {
            id: new Date().getTime().toString(),
            socialUrl,
            socialName,
          },
        },
      }
    );
    res.status(201).json({ success: true, msg: result });
  } catch (err) {
    res.status(500).json({ success: false, msg: err });
  }
});

server.delete("/logout", async (req, res) => {
  try {
    res.clearCookie("ACCESS");
    res.status(200).json({ success: true, msg: "Logout successful" });
  } catch (err) {
    res.status(500).json({ success: false });
  }
});

server.post("/remove", async (req, res) => {
  try {
    const { username, updates } = req.body;
    await db
      .collection("users")
      .updateOne({ username }, { $pull: { social: updates } });
    res.status(200).json({ msg: "Deleted succesfully." });
  } catch (err) {
    res.status(500).json({ msg: err });
  }
});

server.delete("/delete", async (req, res) => {
  try {
    const { username, public_id } = req.body;
    await db.collection("users").deleteOne({ username });
    cloudinary.v2.uploader.destroy(public_id, (err, result) => {
      if (err) return res.status(400).json({ msg: err });
    });
    res.clearCookie("ACCESS");
    res.status(200).json({ success: true, msg: "User deleted succesfully" });
  } catch (err) {
    res.status(500).json({ msg: err });
  }
});

server.put("/upload", async (req, res) => {
  try {
    const { url, public_id, username } = req.body;
    await db
      .collection("users")
      .updateOne({ username }, { $set: { profile: { url, public_id } } });
    res.status(200).json({ success: true });
  } catch (err) {
    res.status(500).json({ msg: err });
  }
});

server.post("/deletePicture", (req, res) => {
  const { public_id } = req.body;
  cloudinary.v2.uploader.destroy(public_id, (err, result) => {
    if (err) return res.status(400).json({ msg: err });
    res.status(200).json({ result });
  });
});

server.get("/clear", async (req, res) => {
  try {
    await db.collection("users").deleteMany();
    res.clearCookie("ACCESS");
    res.send("yes");
  } catch (err) {
    res.send(err);
  }
});
