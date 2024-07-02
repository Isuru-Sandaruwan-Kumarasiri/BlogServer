import express, { response } from 'express'
import mongoose from 'mongoose'
import 'dotenv/config';
import bcrypt from 'bcrypt'
import User from './Shema/User.js';
import { nanoid } from 'nanoid';
import jwt from 'jsonwebtoken'
import cors from 'cors'//avoid to call  default localhost port number
import aws from 'aws-sdk';
import Blog from './Shema/Blog.js';


// import admin from 'firebase-admin';
// import serviceAccount from "./myblog-mern-stack-firebase-adminsdk-1gzt8-a1acee71d1.json" assert { type: "json" }
// import { getAuth } from 'firebase-admin/auth';




const server=express();
let PORT=3000;

//google authentication
// admin.initializeApp({
//     credential: admin.credential.cert(serviceAccount)
//   });







let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; // regex for email
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/; // regex for password

server.use(express.json());
server.use(cors())





mongoose.connect(process.env.DB_LOCATION,{
    autoIndex:true
    
})

//S3 bucket

const s3=new aws.S3({
    region:'eu-north-1',
    accessKeyId:process.env.AWS_ACCESSS_KEY,
    secretAccessKey:process.env.AWS_SECRET_ACCESS_KEY
})

const generateUploadURL=async()=>{
     
    const data=new Date();
    const imageName=`${nanoid()}-${data.getTime()}.jpeg`;

    return await s3.getSignedUrlPromise('putObject',{

        Bucket:'rect-blog',
        Key: imageName,
        Expires:1000,
        ContentType:"image/jpeg"
    })
}




















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



//upload image url route
server.get('/get-upload-url',(req,res)=>{

    generateUploadURL().then(url=> res.status(200).json({uploadURL:url}))
    .catch(err=>{
        console.log(err.message)
        return res.status(500).json({error:err.message})
    })
})












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

// server.post("/google-auth",async (req,res)=>{

//     let {access_token}=req.body;

//     getAuth().verifyIdToken(access_token)
//     .then(async(decodeUser)=>{
        

//         let {email,name,picture}=decodeUser;
//         picture =picture.replace("s96-c","s384-c")
        
//         let user=await User.findOne({"personal_info.email":email})
//         .select(
//             "personal_info.fullname personal_info.username personal_info.profile_img google_auth"
//         ).then((u)=>{
//             return u || null
//         })
//         .catch(err=>{
//             return res.status(500).json({"error":err.message})
//         })
//         console.log(user)
//         if(user){//login
//             if(!user.google_auth){
//                 return res.status(403).json({"error":"This email was signed up without google.please log in with password to access the account"})
//             }
//         }else{//signup
            
//             let username=await generateUsername(email)

//             user=new User({
//                 personal_info:{fullname:name ,email,profile_img:picture,username},
//                 google_auth:true
//             })
//             await user.save().then((u)=>{
//                 user=u
//             })
//             .catch(err=>{
//                 return res.status(500).json({"error":err.message})
//             })
//         }
//         return res.status(200).json(formatDataSend(user))

//     })
//     .catch(err=>{
//         return res.status(500).json({"error":"Failed to authenticte you with google .try with some google account"})
//     })


// })





const verifyJWT=(req,res,next)=>{

    const authHeader =req.headers['authorization']; // this include authorization='Bearer token'
    const token =authHeader && authHeader.split(" ")[1];
    if(token==null){
        return res.status(401).json({error:'No access token'})
    }
    jwt.verify(token,process.env.SECRET_ACCESS_KEY,(err,user)=>{
        if(err){
            return res.status(403).json({error:'access token is invalid'})
        }

        req.user=user.id
        next()
    })

}

server.post("/latest-blogs",(req,res)=>{

    let {page}=req.body;

    let maxLimit=5;

    Blog.find({draft:false})
    .populate("author"," personal_info.profile_img personal_info.username personal_info.fullname -_id")
    .sort({"publishedAt":-1})
    .select("blog_id title des banner activity tags publishedAt -_id")
    .skip((page-1)*maxLimit)
    .limit(maxLimit)
    .then(blogs=>{
        return res.status(200).json({blogs})
    })
    .catch(err=>{
        return res.status(500).json({error:err.message})
    })
})

//all-latest-blogs-count


server.post("/all-latest-blogs-count",(req,res)=>{

   Blog.countDocuments({draft:false})
   .then(count=>{
       return res.status(200).json({totalDocs:count})
   })
   .catch(err=>{
      console.log(err.message);
      return res.status(500).json({error:err.message});
   })
})


//search-blogs-count

server.post("/search-blogs-count",(req,res)=>{

    let {tag,query}=req.body;

    // let findQuery={tags:tag,draft:false};

    let findQuery;

    if(tag){
        findQuery={tags:tag,draft:false};
    }else if(query){
        findQuery={draft:false,title:new RegExp(query,'i')};
    }


    Blog.countDocuments(findQuery)
    .then(count=>{
        return res.status(200).json({totalDocs:count})
    })
    .catch(err=>{
        return res.status(500).json({error:err.message})
    })

     
})








//Ternding Blogs

server.get('/trending-blogs',(req,res)=>{

    Blog.find({draft:false})
    .populate("author"," personal_info.profile_img personal_info.username personal_info.fullname -_id")
    .sort({"activity.total_read":-1,"activity.total_likes":-1 ,"publishedAt":-1})
    .select("blog_id title des  publishedAt -_id")
    .limit(5)
    .then(blogs=>{
        return res.status(200).json({blogs})
    }).catch(err=>{
        return res.status(500).json({error:err.message})  
    })
})



server.post("/search-blogs",(req,res)=>{

    let {tag,query,page}=req.body;

    let findQuery;

    if(tag){
        findQuery={tags:tag,draft:false};
    }else if(query){
        findQuery={draft:false,title:new RegExp(query,'i')};
    }

    let maxLimit=2;

    Blog.find(findQuery)
    .populate("author"," personal_info.profile_img personal_info.username personal_info.fullname -_id")
    .sort({"publishedAt":-1})
    .select("blog_id title des banner activity tags publishedAt -_id")
    .skip((page-1)*maxLimit)
    .limit(maxLimit)
    .then(blogs=>{
        return res.status(200).json({blogs})
    })
    .catch(err=>{
        return res.status(500).json({error:err.message})
    })
    
})


//Search user


server.post("/search-users",(req,res)=>{

    let {query}=req.body;

    User.find({"personal_info.username":new RegExp(query,'i')})
    .limit(50)
    .select(" personal_info.profile_img personal_info.username personal_info.fullname -_id")
    .then(users=>{
        return  res.status(200).json({users})
    })
    .catch(err=>{
        return res.status(500).json({error:err.message})
    })
})


server.post("/get-profile",(req,res)=>{

    let {username} =req.body;

   User.findOne({"personal_info.username":username}) 
   .select("-personal_info.password -google_auth -updateAt -blogs")
   .then(user=>{
       return res.status(200).json(user)
   })
   .catch(err=>{
    console.log(err)
       return res.status(500).json({error :err.message})
   })
})









server.post("/create-blog",verifyJWT,(req,res)=>{
    
    //  verify funtion akedi assigned karnwa user id eka
    let authorId=req.user;

    let {title,des,banner,tags,content,draft }=req.body;//destructure from  fronend

    if(!title.length){
        return res.status(403).json({error:'You must provide a title '})
    }


    if(!draft){
        
        if(!des.length||des.length>200){
            return res.status(403).json({error:'You must provide blog description under 200 characters'})
        }
        if(!banner.length){
            return res.status(403).json({error:'YOu must provide blog banner to publish it '})
        }
        if(!content.blocks.length){
           return res.status(403).json({error:"There must be some blog content to publish it"})
        }
        if(!tags.length || tags.length>10){
            return res.status(403).json({error:'Provide tags in order to publish the blog ,Maximum 10'})
        }
    }

    

    


    tags=tags.map(tag=>tag.toLowerCase());

    let blog_id=title.replace(/[^a-zA-Z0-9]/g, ' ').replace(/\s+/g, "-").trim() + nanoid();
    //console.log(blogId)




    let blog=new Blog ({
        title,des,banner,content,tags,author:authorId,blog_id,draft:Boolean(draft)
    })

    blog.save().then(blog=>{

        let incrementVal=draft ? 0:1;
        //console.log(incrementVal)
        User.findOneAndUpdate({_id:authorId},

            {
              $inc:{"account_info.total_posts":incrementVal},
              $push:{"blogs":blog._id}
            }
           
        ).then(user=>{
                return res.status(200).json({id:blog.blog_id})
            }).catch(err=>{
                return res.status(500).json({error:"Faild to update total posts number"})
            })
    }).catch(err=>{
        return res.status(500).json({error:err.message})
    })

   // return res.json({status:"done"});



})





server.listen(PORT,()=>{
    console.log("listening on port"+PORT);
})