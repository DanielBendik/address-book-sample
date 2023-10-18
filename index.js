import express from "express";
import jwt from 'jsonwebtoken';
import bodyParser from "body-parser";
import cookieParser from 'cookie-parser';
import axios from "axios";
import pool from './db.js';
import { requireAuth } from './middleware/auth.js';
import dotenv from 'dotenv';

// Admin
import admin from 'firebase-admin'

// Client 
import firebase from 'firebase/compat/app';
import 'firebase/compat/auth';
import 'firebase/compat/firestore';

// Initialize the admin-side Firebase SDK
import serviceAccount from './strv-addressbook-bendik-daniel-firebase-adminsdk-ozcge-fc5f0ea179.json' assert { type: "json" };
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

// Initialize the client-side Firebase SDK
const firebaseConfig = {
  apiKey: process.env.FIREBASE_API_KEY,
  authDomain: process.env.FIREBASE_AUTH_DOMAIN,
  projectId: process.env.FIREBASE_PROJECT_ID,
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
  messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
  appId: process.env.FIREBASE_APP_ID,
  measurementId: process.env.FIREBASE_MEASUREMENT_ID
};

firebase.initializeApp(firebaseConfig);
const auth = firebase.auth();
const firestore = firebase.firestore();

dotenv.config();

const app = express();  // express app
const port = process.env.PORT || 3000;  // default to localhost:3000
const secretKey = process.env.JWT_SECRET;  // secret key grabbed from .env file

app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());  // used for tokens
app.set('view engine', 'ejs');

app.get("/", async (req, res) => {  // Redirected here if not logged in
  res.render("login.ejs");
});

app.get("/login", async (req, res) => {  // Added for ease of use
  res.render("login.ejs");
});

app.get("/register", async (req, res) => {
  res.render("register.ejs");
});

app.post("/logout", (req, res) => {
  res.clearCookie('token');
  res.redirect('/');
});

export async function registerUser(email, password) 
{  // register new user into database
  const sql = await pool.execute('INSERT INTO users (email, password) VALUE (?, ?);', [email, password]);
  return sql;
}

export async function checkEmail(email)
{  // check email when registering without confirming password is correct
  try {
    const sql = await pool.execute('SELECT * FROM users WHERE email = ?;', [email]);
    return sql;
  } catch (error) {
    throw error;
  }
}

export async function checkLogin(email, password) 
{  // function used to check if any sql object is returned
  try {
    const sql = await pool.execute('SELECT * FROM users WHERE email = ? AND password = ?;', [email, password]);
    return sql;
  } catch (error) {
    throw error;
  }
}

export async function createToken(email, password, res)  // creates a token for the user
{
  try {
    var loginValid = await checkLogin(email, password);  // check if this combination exists

    if (loginValid[0].length > 0) {  // Length of sql 'rows' will be '1' if exists.
      const emailSignature = loginValid[0][0].email;
      const passwordSignature = loginValid[0][0].password;

      // Create a JWT token
      const token = jwt.sign({ email: emailSignature, password: passwordSignature }, secretKey, { expiresIn: '1hr' });
      res.cookie('token', token);  // Store the token in a cookie
      res.redirect('/dashboard');  // Take the user to the API dashboard
    } else {
      res.status(401).json({ error: 'Invalid combination.' });  // Wrong password or email response
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
}

app.post('/login', async (req, res) => {
  const { email, password } = req.body;  // store the email and password from the request body
  createToken(email, password, res);     // create a token when user logs in
});

app.post("/register", async (req, res) => {  // post request when registering for the first time
  const { email, password, confirm } = req.body;

  var emailExists = await checkEmail(email);

  if (emailExists[0].length > 0)  // email shouldn't exist in the database.
  {
    return res.status(400).json({"status": "Email already signed up."});
  }

  if (email.length < 6 || email.length > 255)  // a@a.io is 6 chars and tinytext compatible with 255 chars
  {
    return res.status(400).json({"status": "Email must be between 6 and 255 characters (inclusive.)"});
  }

  if (password.length < 8 || password.length > 255)  
  {
    return res.status(400).json({"status": "Password must be between 8 and 255 characters (inclusive.)"});
  }

  if (password != confirm)
  {
    return res.status(400).json({"status": "Passwords do not match."});
  }

  await registerUser(email, password);  // If they passed all the above, add them to database

  firebase.auth().onAuthStateChanged(user => {  // Check if auth state is changed
    if (user) {
      console.log("Authenticated.");
    } else {
      console.log("Waiting for Firebase...");
    }
  });

  try {  //  Register user with Firebase
    await auth.createUserWithEmailAndPassword(email, password);

    /*
    const userRef = firestore.collection('users').doc(email);  // Use email to index documents
    const usersContacts = userRef.collection('contacts');      // grab contacts collection

    await usersContacts.doc("DanielBendik").set({              // (Delete this before submission)
      firstName: 'Daniel',
      lastName: 'Bendik',
      phone: '2242457812',
      address: 'Chicago, IL'
    });
    */

  } catch (error) {
    console.error("Registration error:", error.message);
    res.redirect("/register");  // Redirect back to registration page on error
  }

  createToken(email, password, res);  // create a token when user registers on website
});

app.get("/dashboard", requireAuth, async (req, res) => {
  const token = req.cookies.token;  // get the stored token from cookie 

  try {
      const decoded = jwt.verify(token, secretKey); // Decode user data from payload

      var loginValid = await checkLogin(decoded.email, decoded.password);  // Double check
      if (loginValid[0].length <= 0) {  // If the login does not exist, redirect them to login
        return res.redirect('/');
      }

      var fireEmail = decoded.email;
      var firePassword = decoded.password;
      await auth.signInWithEmailAndPassword(fireEmail, firePassword);

      // const success = req.query.success === 'true';  // create boolean for success message
      /*
        <% if (locals.success) { %>
          <% if (success) { %>
            <div class="success-message">Contact added successfully!</div>
          <% } else { %>
            <div class="error-message">An error occurred while adding the contact.</div>
          <% } %>
        <% } %>
      */

      res.render("dashboard.ejs", { emailKey: fireEmail });
      
      } catch (error) {
        console.error(error);
        res.redirect('/');  // double safety measure despite having redirect in requireAuth
      }
});

app.post('/dashboard/addContact', requireAuth, async (req, res) => {  // POST request to send to Firestore
  const token = req.cookies.token; // Get the stored token from cookie

  try {
    const decoded = jwt.verify(token, secretKey); // Decode user data from payload
    var fireEmail = decoded.email;

    const { firstName, lastName, phone, address } = req.body;
    const userRef = firestore.collection('users').doc(fireEmail);  // Use email to index documents
    const usersContacts = userRef.collection('contacts');          // grab contacts collection
    
    var concat = firstName + lastName;

    await usersContacts.doc(concat).set({  // Set "contacts" document index to their first and last name
      firstName: firstName,
      lastName: lastName,
      phone: phone,
      address: address
    });

    res.redirect('/dashboard?success=true');  // When done, take the user back to the form.

  } catch (error) {
    console.error(error);
    res.redirect('/dashboard?success=false');
  }

});

app.listen(port, () => {
    console.log(`Server running on port: ${port}`);
});