import dotenv from 'dotenv';

dotenv.config({path:"../../.env.backends"});

console.log("Test backend running...");

console.log(process.env.TEST)