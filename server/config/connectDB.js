const mongoose = require('mongoose')

async function connectDB(){
    try {
        await mongoose.connect(process.env.MONGODB_URI)
        .then(() => {
            console.log("MongoDB is connected Successfully")
        })
        .catch((err) => {
            console.log("Error is DataBase Connection")
            console.error(err);
        });
    } catch (error) {
        console.log("MongoDB is not Connected ",error)
    }
}

module.exports = connectDB