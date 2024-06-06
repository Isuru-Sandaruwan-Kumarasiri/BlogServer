import express from 'express'
import mongoose from 'mongoose'
import 'dotenv/config';
import bcrypt from 'bcrypt'
import User from './Shema/User.js';
import { nanoid } from 'nanoid';
import jwt from 'jsonwebtoken'
import cors from 'cors'//avoid to call  default localhost port number


import admin from 'firebase-admin';
import serviceAccountKey from './myblog-mearn-stack-firebase-adminsdk-cl2ul-9eaf637df1.json' assert { type: "json" };
import { getAuth } from 'firebase-admin/auth';




const server=express();
let PORT=3000;

//google authentication
admin.initializeApp({
    
    credential:admin.credential.cert(serviceAccountKey)


})







let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; // regex for email
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/; // regex for password

server.use(express.json());
server.use(cors())

mongoose.connect(process.env.DB_LOCATION,{
    autoIndex:true
    
})



const generateUsername=async (email)=>{
    let username=email.split("@")[0];
    
    let isUsernameNotUnique=await User.exists({"personal_info":username}).then((result)=>result);
     isUsernameNotUnique ? username+=nanoid().substring(0,5):"";
    return username;
    
}


const formatDataSend=(user)=>{

     const access_token=jwt.sign({id: user._id},process.env.SECRET_ACCESS_KEY)

    return{
        access_token,
        profile_img:user.personal_info.profile_img,
        username:user.personal_info.username,
        fullname:user.personal_info.fullname,

    }
}



server.post("/signup",(req,res)=>{
    
    
    let {fullname,password,email}=req.body;

    if(fullname.length<3){
        return res.status(403).json({"error":"full name must be at least  3 letters long "})
    }
    if(!email.length){
        return res.status(403).json({"error":"Enter email"})
    }
    if(!emailRegex.test(email)){
        return res.status(403).json({"error":"Email is invalid"})
    }
    if(!passwordRegex.test(password)){
        return res.status(403).json({"error":"password should be 6 to 20 charchters long with a numeric ,1 lowercase and 1 upercase letterss"})
    }



    bcrypt.hash(password,10,async (err,hashed_password)=>{

        let username= await generateUsername(email);
        let user=new User({
            personal_info:{fullname,email,password:hashed_password,username}
        })
        user.save().then((u)=>{
            // return res.status(200).json({user:u})
            return res.status(200).json(formatDataSend(u))

        })
        .catch(err=>{

            if(err.code==11000){
                return res.status(500).json({"error":"Email already exists"})
            }
            return res.status(500).json({"error":err.message})
        })
        // console.log(hashed_password)
    })
    
   
    

}) 




server.post("/signin",(req,res)=>{
    
    let {email,password}=req.body;

    User.findOne({"personal_info.email":email})
    .then((user)=>{
        if(!user){
            return res.status(403).json({"error":"email not found"})
        }


       bcrypt.compare(password,user.personal_info.password,(err,result)=>{

        if(err){
            return res.status(403).json({"error":"Error occured while login try again"})

        }
        if(!result){
            return res.status(403).json({"error":"incorrect passowrd"})
        }else{
            return res.status(200).json(formatDataSend(user))

        }
       })




        
        // return res.json({"status":"got user documnet"})
    })
    .catch(err=>{
        console.log(err.message);
        return res.status(500).json({"error":err.message})

    })
})



//google authentiaction

server.post("/google-auth",async (req,res)=>{

    let {access_token}=req.body;

    getAuth().verifyIdToken(access_token)
    .then(async(decodeUser)=>{
        

        let {email,name,picture}=decodeUser;
        picture =picture.replace("s96-c","s384-c")
        
        let user=await User.findOne({"personal_info.email":email})
        .select(
            "personal_info.fullname personal_info.username personal_info.profile_img google_auth"
        ).then((u)=>{
            return u || null
        })
        .catch(err=>{
            return res.status(500).json({"error":err.message})
        })
        console.log(user)
        if(user){//login
            // if(!user.google_auth){
            //     return res.status(403).json({"error":"This email was signed up without google.please log in with password to access the account"})
            // }
        }else{//signup
            
            let username=await generateUsername(email)

            user=new User({
                personal_info:{fullname:name ,email,profile_img:picture,username},
                google_auth:true
            })
            await user.save().then((u)=>{
                user=u
            })
            .catch(err=>{
                return res.status(500).json({"error":err.message})
            })
        }
        return res.status(200).json(formatDataSend(user))

    })
    .catch(err=>{
        return res.status(500).json({"error":"Failed to authenticte you with google .try with some google account"})
    })


})








server.listen(PORT,()=>{
    console.log("listening on port"+PORT);
})