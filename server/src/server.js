import connectDB from "./db/index.js";
import dotenv from "dotenv"
import app from "./app.js";


dotenv.config({
    path: '../.env'
})

connectDB()
.then(() => {

    const server = app.listen(process.env.PORT || 2000 ,() => {
        console.log(`⚙️ Server is running at port : ${process.env.PORT}`);
    })

    server.on("error" , (err) => {
        console.log(`❌ Server error: ${err.message}`)
    })
})
.catch((err) =>{
    console.log("❌ MONGO DB connection failed !!!", err);
})