import mongoose from "mongoose";

const connectDB = async (DATABASE_URL) => {
    try {
        const DB_OPTIONS = {
            dbName: process.env.DB_NAME,
        }
        await mongoose.connect(DATABASE_URL, DB_OPTIONS);
        console.log('Database connected successfully');
        
    } catch (error) {
        console.error('Error connecting to database:', error.message);
    }
}

export default connectDB;