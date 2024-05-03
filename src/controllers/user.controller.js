import { asyncHandler } from "../utils/asyncHandler.js"
import { ApiError } from "../utils/ApiError.js"
import { User } from "../models/user.model.js"
import {uploadOnCloudinary} from "../utils/cloudinary.js"
import { ApiResponse } from "../utils/ApiResponse.js"

const registerUser = asyncHandler(async (req, res) => {
    const {username, email, password, fullName} = req.body
    console.log("email: ", email);

    if(
        [fullName, email, password, username].some((field) => field?.trim() === "")
    ){
        throw new ApiError(400, "All fields are compulsory")
    }

    const existingUser = User.findOne({
        $or : [{ email }, { username }]
    })

    if(existingUser){
        throw new ApiError(409, "User with this email or username already exists")
    }

    const avatarLocalPath = req.files?.avatar[0]?.path;
    const coverImageLocalPath = req.files?.coverImage[0]?.path;

    if(!avatarLocalPath){
        throw new ApiError(400, "Avatar file is required");
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if(!avatar){
        throw new ApiError(400, "Avatar file is required");
    }

    const user = await User.create({
        fullName,
        avatar : avatar.url,
        coverImage : coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase()
    })

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    if(!createdUser){
        throw new error(500, "Something went wrong while registering the user")
    }

    return res.status(201).json(
        new ApiResponse(200, createdUser, "User registered succesfully!")
    )
})

export {registerUser}

/*
register user logic:

1. get user details from the frontend (GET request from postman in this case)
2. validation - check if empty or not empty
3. check if user already exists: username and email (any one of them is also fine)
4. check for images and avatar
5. upload them to cloudinary, also check on cloudinary if avatar is successfully uploaded (required field)
6. create user object - create entry in db
7. remove password and refresh token field from response
8. check for user creation in the response (if response is giving a user or null)
9. return response

*/