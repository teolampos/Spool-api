const express = require("express");
const { MongoClient } = require("mongodb");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const helmet = require("helmet");
const xss = require("xss-clean");
const rateLimiter = require("express-rate-limit");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cloudinary = require("cloudinary");
require("dotenv").config();

const PORT = process.env.PORT || 5003;
const server = express();
//We connect to the MongoDB database
let db;
MongoClient.connect(process.env.MONGO_URI)
  .then((client) => {
    db = client.db();
    server.listen(PORT, () =>
      console.log("Server started listening on PORT", PORT)
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

//MIDDLEWARES
server.use(express.json()); //TO ACCEPT JSON
server.use(cookieParser()); // TO WORK WITH COOKIES
//SECURITY MIDDLEWARES
server.use(helmet());
server.use(xss());
server.set("trust proxy", 1);
server.use(rateLimiter({ windowMs: 5 * 60 * 1000, max: 100 }));

//Implementing CORS
server.use(
  cors({
    origin: ["http://localhost:3000", "https://spool.onrender.com"],
    credentials: true,
  })
);

//--------ROUTES------------//

//REGISTER ROUTE
server.post("/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    //CHECKS IF A USER WITH THE EXACT USERNAME IS ALREADY REGISTERED
    const sameUser = await db.collection("users").findOne({ username });
    if (sameUser != null) {
      return res.status(400).json({ msg: "User already exists" });
    }

    //HASHING USER PASSWORD
    let salt = await bcrypt.genSalt();
    let hashedPassword = await bcrypt.hash(password, salt);
    let user = {
      username,
      email,
      password: hashedPassword,
      profilePicture: null,
      userPlatforms: [],
    };
    await db.collection("users").insertOne(user);

    //GENERATING JWT TOKEN AND SEND IT AS AN HTTP-ONLY COOKIE
    user = { username, profilePicture: user.profilePicture };
    const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET);
    res.cookie("ACCESS", token, {
      httpOnly: true,
      secure: "",
      sameSite: "none",
      maxAge: 24 * 60 * 1000, // COOKIE EXPIRES IN ONE DAY FROM THE MOMENT OF CREATION
    });

    res.status(201).json({ msg: "User added", user });
  } catch (err) {
    res.status(500).json({ msg: "Internal Server Error" });
  }
});

//LOGIN ROUTE
server.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    //CHECK IF USER EXISTS
    let user = await db.collection("users").findOne({ username });
    if (user == null) {
      return res.status(404).json({ msg: "No such user" });
    }
    //IF AUTHENTICATION IS CORRECT, THEN GENERATE JWT TOKEN AND SEND IT AS AN HTTP-ONLY COOKIE
    if (await bcrypt.compare(password, user.password)) {
      let token = await jwt.sign(
        {
          username,
          profilePicture: user.profilePicture ? user.profilePicture.url : null,
        },
        process.env.ACCESS_TOKEN_SECRET
      );
      res.cookie("ACCESS", token, {
        httpOnly: true,
        secure: "",
        sameSite: "none",
        maxAge: 24 * 60 * 1000, // COOKIE EXPIRES IN ONE DAY FROM THE MOMENT OF CREATION
      });
      res.status(200).json({ username });
    } else {
      res.status(403).json({ msg: "Wrong password" });
    }
  } catch (err) {
    res.status(500).json({ msg: "Internal Server Error" });
  }
});

//LOGOUT ROUTE
server.delete("/logout", async (req, res) => {
  try {
    res.clearCookie("ACCESS", {
      httpOnly: true,
      secure: true,
      sameSite: "none",
    });
    res.status(200).json({});
  } catch (err) {
    res.status(500).json({ success: false });
  }
});

//AUTHORIZATION ROUTE
server.get("/auth", (req, res) => {
  const { ACCESS } = req.cookies;
  if (ACCESS) {
    jwt.verify(ACCESS, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
      if (err) return res.status(403).json({ msg: "Unauthorized" });
      res.status(200).json(user);
    });
  } else res.status(403).json({ msg: "Unauthorized" });
});

//ROUTE TO GET ALL SOCIAL MEDIA PLATFORMS
server.get("/platforms", async (req, res) => {
  try {
    let platforms = [];
    await db
      .collection("platforms")
      .find()
      .sort({ name: 1 })
      .forEach((platform) => platforms.push(platform));
    res.status(200).json(platforms);
  } catch (err) {
    res.status(500).json({ msg: err });
  }
});

//ROUTE TO GET USER INFO
server.get("/users/:username", async (req, res) => {
  try {
    let user = await db
      .collection("users")
      .findOne({ username: req.params.username });
    if (user == null) res.status(404).json("No such user exists");
    let platforms = [];
    await db
      .collection("platforms")
      .find()
      .forEach((element) => platforms.push(element));
    res.status(200).json({
      empty: user.userPlatforms.length == 0 ? true : false,
      userPlatforms: user.userPlatforms,
      profilePicture: user.profilePicture,
      platforms,
    });
  } catch (err) {
    res.status(500).json({ msg: "Internal Server Error" });
  }
});

//ROUTE TO CONNECT A SOCIAL PLATFORM TO A USER'S SPOOL ACCOUNT
server.put("/add", async (req, res) => {
  try {
    const { username, socialUrl, socialName } = req.body;
    const result = await db.collection("users").updateOne(
      { username },
      {
        $push: {
          userPlatforms: {
            id: new Date().getTime().toString(),
            socialUrl,
            socialName,
          },
        },
      }
    );
    res.status(201).json({ msg: result });
  } catch (err) {
    res.status(500).json({ msg: "Internal Server Error" });
  }
});

//ROUTE TO REMOVE A CONNECTED SOCIAL PLATFORM FROM USER'S ACCOUNT
server.post("/remove", async (req, res) => {
  try {
    const { username, updates } = req.body;
    await db
      .collection("users")
      .updateOne({ username }, { $pull: { userPlatforms: updates } });
    res.status(200).json({ msg: "Deleted succesfully." });
  } catch (err) {
    res.status(500).json({ msg: "Internal Server Error" });
  }
});

//DELETE USER ROUTE
server.delete("/delete", async (req, res) => {
  try {
    const { username, public_id } = req.body;
    res.clearCookie("ACCESS", {
      httpOnly: true,
      secure: true,
      sameSite: "none",
    });
    await db.collection("users").deleteOne({ username });
    if (public_id) {
      cloudinary.v2.uploader.destroy(public_id, (err, result) => {
        if (err) return res.status(400).json({ msg: err });
      });
    }
    res.status(200).json({});
  } catch (err) {
    res.status(500).json({ msg: err });
  }
});

//UPLOAD PROFILE PICTURE ROUTE
server.put("/upload", async (req, res) => {
  try {
    //IF A PICTURE IS ALREADY SET, WE DELETE IT
    const { url, public_id, username, delete_id } = req.body;
    if (delete_id !== null) {
      cloudinary.v2.uploader.destroy(delete_id, (err, result) => {
        if (err) return res.status(400).json({ msg: err });
      });
    }
    //SAVE THE IMAGE URL AND PUBLIC_ID ON THE DATABASE
    await db
      .collection("users")
      .updateOne(
        { username },
        { $set: { profilePicture: { url, public_id } } }
      );
    res.status(200).json({ success: true });
  } catch (err) {
    res.status(500).json({ msg: "Internal Server Error" });
  }
});
