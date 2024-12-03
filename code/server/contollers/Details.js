const User = require("../models/User");


exports.getStudentDetails = async(req, res) => {
    try{
        const {email} = req.body ;

        // console.log("Email : ", email) ;

        if(!email){
            return res.status(400).json({
                success: false,
                message: "Email is required for fetching student's details"
            }) ;
        }

        const studentDetails = await User.find({ email }) ;

        console.log("Student info : ", studentDetails) ;

        return res.status(200).json({
            success: true,
            message: "Student's details fetched Successfully.",
            studentDetails,
        }) ;
    }
    catch(err){
        return res.status(400).json({
            success: false,
            message: "Error occured in fetching Student's details.",
            error: err.message
        }) ;
    }
}

exports.getInstructorDetails = async(req, res) => {
    try{
        const {email} = req.body ;

        console.log("Email : ", email) ;

        if(!email){
            return res.status(400).json({
                success: false,
                message: "Email is required for fetching instructor's details"
            }) ;
        }

        const instructorDetails = await User.find({ email }) ;

        console.log("User info : ", instructorDetails) ;

        return res.status(200).json({
            success: true,
            message: "Instructor's details fetched Successfully.",
            instructorDetails
        }) ;
    }
    catch(err){
        return res.status(400).json({
            success: false,
            message: "Error occured in fetching Instructor's details.",
            error: err.message
        }) ;
    }
}

exports.getAdminDetails = async(req, res) => {
    try{
        const {email} = req.body ;

        console.log("Email : ", email) ;

        if(!email){
            return res.status(400).json({
                success: false,
                message: "Email is required for fetching Admin's details"
            }) ;
        }

        const adminDetails = await User.find({ email }) ;

        console.log("User info : ", adminDetails) ;

        return res.status(200).json({
            success: true,
            message: "Admin's details fetched Successfully.",
            adminDetails
        }) ;
    }
    catch(err){
        return res.status(400).json({
            success: false,
            message: "Error occured in fetching Admin's details.",
            error: err.message
        }) ;
    }
}