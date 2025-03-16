import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import connectDB from './config/connectdb.js';
import passport from 'passport';
import userRoutes from './routes/user.routes.js';
import './config/passport-jwt-strategy.js';


const corsOptions = {
    origin: process.env.FRONTEND_URL,
    credentials: true,
    optionsSuccessStatus: 200,
};


dotenv.config();
const app = express();

app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());
app.use(passport.initialize());

const port = process.env.PORT;
const DATABASE_URL = process.env.DATABASE_URL;

connectDB(DATABASE_URL);

app.use("/api/user",userRoutes)

app.listen(port, () => {
    console.log(`Server is running on port http://localhost:${port}`);
});