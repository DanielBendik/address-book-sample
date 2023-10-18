import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
dotenv.config();

const secretKey = process.env.JWT_SECRET;  // grab secret from .env file

export function requireAuth(req, res, next) {
  const token = req.cookies.token; // get the token from the cookie

  if (!token) {
    return res.redirect('/'); // redirect to login page if there's no token set
  }

  try {
    jwt.verify(token, secretKey); // verify token with my secret key
    next(); // If token is valid, proceed 
  } catch (error) {
    console.error(error);
    return res.redirect('/'); // Redirect to login page if token is invalid
  }
}
