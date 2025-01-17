import mongoose from "mongoose"; 


const connectDB = async () => {  // Define an asynchronous function to connect to MongoDB
  try {  // Start a try block to handle potential errors
    const connectionInstance = await mongoose.connect(  // Await the connection to MongoDB
      `${process.env.MONGODB_URI}`  // Use the environment variable and DB_NAME for the connection string
    );
    console.log(  // Log a message if the connection is successful
      `\n MongoDB connected !! DB HOST: ${connectionInstance.connection.host}`  // Display the host of the connected database
    );
  } catch (error) {  // Catch block to handle errors if the connection fails
    console.log("MONGODB connection FAILED ", error);  // Log the error message
    process.exit(1);  // Exit the process with failure code
  }
};

export default connectDB;  // Export the connectDB function as the default export
