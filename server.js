import express, { response } from 'express'
import mongoose from 'mongoose'
// import 'dotenv/config';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt'
import User from './Shema/User.js';
import { nanoid } from 'nanoid';
import jwt from 'jsonwebtoken'
import cors from 'cors'//avoid to call  default localhost port number
//import aws from 'aws-sdk';
import Blog from './Shema/Blog.js';
import Notification from './Shema/Notification.js';
import Comment from './Shema/Comment.js'


dotenv.config();
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

// const s3=new aws.S3({
//     region:'eu-north-1',
//     accessKeyId:process.env.AWS_ACCESSS_KEY,
//     secretAccessKey:process.env.AWS_SECRET_ACCESS_KEY
// })

// const generateUploadURL=async()=>{
     
//     const data=new Date();
//     const imageName=`${nanoid()}-${data.getTime()}.jpeg`;

//     return await s3.getSignedUrlPromise('putObject',{

//         Bucket:'rect-blog',
//         Key: imageName,
//         Expires:1000,
//         ContentType:"image/jpeg"
//     })
// }

import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { fromEnv } from "@aws-sdk/credential-providers";
import { config, populate } from 'dotenv';


// Create an S3 client
const s3Client = new S3Client({
    region: 'eu-north-1',
    credentials: {
        accessKeyId:process.env.AWS_ACCESSS_KEY,
       secretAccessKey:process.env.AWS_SECRET_ACCESS_KEY
    }
  });
  

const generateUploadURL = async () => {
  const data = new Date();
  const imageName = `${nanoid()}-${data.getTime()}.jpeg`;

  const command = new PutObjectCommand({
    Bucket: 'rect-blog',
    Key: imageName,
    ContentType: "image/jpeg",
  });

  const signedUrl = await getSignedUrl(s3Client, command, { expiresIn: 1000 });
  return signedUrl;
};



















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
server.get("/get-upload-url",(req,res)=>{

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

server.post("/change-password",verifyJWT,(req,res)=>{
    
    let {currentPassword ,newPassword}=req.body;

    if(!passwordRegex.test(currentPassword) || !passwordRegex.test(newPassword)){
        return res.status(403).json({error :"password should be 6 to 20 charchters long with a numeric ,1 lowercase and 1 upercase letters"});
    }
    User.findOne({_id:req.user})
    .then((user)=>{

        if(user.google_auth){
            return res.status(403).json({error:"you can't change account's password because you logged in through google"})
        }
        
        
        bcrypt.compare(currentPassword,user.personal_info.password,(err,result)=>{

            if(err){
                return res.status(500).json({error:"some error occured while changing  the password ,pleace try again later"})
            }
            if(!result){
                return res.status(403).json({error:"Incorrect current Password"})
            }
            bcrypt.hash(newPassword,10,(err,hashed_password)=>{

                User.findOneAndUpdate({_id:req.user},{"personal_info.password":hashed_password})
                .then((u)=>{
                    return res.status(200).json({status:'Password Changed'})
                })
                .catch(err=>{
                    return res.status(500).json({error:'Some error occoured while saving new password ,pleace try again later'})
                })
            })

        })

    })
    .catch(err=>{
        console.log(err)
        res.status(500).json({error:'user not found'})
    })
})

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

    let {tag,query,author}=req.body;

    // let findQuery={tags:tag,draft:false};

    let findQuery;

    if(tag){
        findQuery={tags:tag,draft:false};
    }else if(query){
        findQuery={draft:false,title:new RegExp(query,'i')};
    }else if(author){
        findQuery={author,draft:false};
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

    let {tag,query,author,page,limit,eliminate_blog}=req.body;

    let findQuery;

    if(tag){
        findQuery={tags:tag,draft:false,blog_id:{$ne:eliminate_blog}};//dant tiyena blog id eka natuwa tag[0] blog ekak seveema($ne=Not equal)
    }else if(query){
        findQuery={draft:false,title:new RegExp(query,'i')};
    }else if(author){
        findQuery={author,draft:false};
    }

    let maxLimit=limit ? limit :2;

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




//uploadimg
server.post("/update-profile-img",verifyJWT,(req,res)=>{

    let {url}=req.body;
    
    User.findOneAndUpdate({_id:req.user},{"personal_info.profile_img":url})
    .then(()=>{
        return res.status(200).json({profile_img:url})
    })
    .catch(err=>{
        return res.status(500).json({error:err.message})
    })
})
//update profile 
server.post("/update-profile",verifyJWT,(req,res)=>{

    let {username,bio,social_links}=req.body;

    let bioLimit=150;

    if(username.length<3){
        return res.status(403).json({error:"Username should be at least loang"})
    }
    if(bioLimit<bio.length){
        return res.status(403).json({error:`Bio should not be more than ${bioLimit}`})
    }

    let socialLinksArr=Object.keys(social_links);
    try {

        for(let i=0;i<socialLinksArr.length;i++){
            if(social_links[socialLinksArr[i]].length){
                let hostname=new URL(social_links[socialLinksArr[i]]).hostname;

                if(!hostname.includes(`${socialLinksArr[i]}.com`) &&  socialLinksArr[i] !='website'){
                    return res.status(403).json({error :`${socialLinksArr[i]} link is invalid .You must enter a full links`})
                }
            }
        }
        
    } catch (error) {
        return res.status(500).json({error:`You must provide full social links with http(s) included`})
    }

    let UpdateObj={
       
        "personal_info.username":username,
        "personal_info.bio":bio,
        social_links
    }
    User.findOneAndUpdate({_id:req.user},UpdateObj,{runValidators :true})
    .then(()=>{
        return res.status(200).json({username})
    })
    .catch(err =>{
        if(err.code ==11000){
            return res.status(409).json({error :"username is already taken"})
        }
        return res.status(500).json({error :err.message})
    })
})




server.post("/create-blog",verifyJWT,(req,res)=>{
    
    //  verify funtion akedi assigned karnwa user id eka
    let authorId=req.user;

    let {title,des,banner,tags,content,draft,id }=req.body;//destructure from  fronend

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

    let blog_id=id || title.replace(/[^a-zA-Z0-9]/g, ' ').replace(/\s+/g, "-").trim() + nanoid();
    //console.log(blogId)

    if(id){

        Blog.findOneAndUpdate({blog_id},{ title,des,banner,content,tags,draft:draft?draft:false})
        .then(blog=>{
            return res.status(200).json({id:blog_id});
        })
        .catch(err=>{
            return res.status(500).json({error:err.message})
        })

    }else{

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

    }


   



})



//render blogpage

server.post("/get-blog",(req,res)=>{

    let {blog_id,draft,mode}=req.body;

    let incrementVal= mode != "edit" ? 1:0 ;

    Blog.findOneAndUpdate({blog_id},{$inc :{"activity.total_reads":incrementVal}})      // blog_id:blog_id //and increased increment value
    .populate("author"," personal_info.profile_img personal_info.username personal_info.fullname ")
    .select("blog_id content title des banner activity tags publishedAt")
    .then(blog=>{
        
        User.findOneAndUpdate({"personal_info.username":blog.author.personal_info.username},{$inc:{"account_info.total_reads":incrementVal}})
        .catch(err=>{
            return res.status(500).json({error:err.message})
        })
        if(blog.draft && !draft){
            return res.status(500).json({error:'you can not access draft blogs'})
        }


        return res.status(200).json({blog})
    })
    .catch(err=>{
        return res.status(500).json({error:err.message})
    })
})  

//get the liked information

server.post("/like-blog",verifyJWT,(req,res)=>{

    //console.log(req)
    
    let user_id=req.user;

    let { _id,islikeByUser}=req.body;

    let incrementVal= !islikeByUser ? 1:-1;

    Blog.findOneAndUpdate({_id},{$inc:{"activity.total_likes":incrementVal}})
    .then(blog=>{
        
        if(!islikeByUser){
           let like=new Notification ({
                type:"like",
                blog:_id,
                notification_for:blog.author,
                user:user_id
           })

           like.save().then(notification=>{
              return res.status(200).json({liked_By_user:true})
           })
        }else{
            Notification.findOneAndDelete({user:user_id,blog:_id,type:"like"})
            .then(data=>{
                return res.status(200).json({liked_By_user:false})
            })
            .catch(err=>{
                return res.status(500).json({error:err.message})
            })
        }
    })


})





//

server.post("/isliked-by-user",verifyJWT,(req,res)=>{
    
    let user_id=req.user;

    let {_id}=req.body;

    Notification.exists({user:user_id,type:"like",blog:_id})
    .then(result=>{
        return res.status(200).json({result})//true or false
    })
    .catch(err=>{
        return res.status(500).json({error:err.message})
    })






})

server.post("/add-comment",verifyJWT,(req,res)=>{

    let user_id=req.user;

    let {_id,comment,replying_to,blog_author}=req.body;

    if(!comment.length){
        return res.status(403).json({error:'Write something to leave a comment'})
    }
    //creating a comment doc
    let commentObj={
        blog_id:_id,blog_author,comment, commented_by:user_id,
    }

    if(replying_to){
        commentObj.parent=replying_to;
        commentObj.isReply=true;
    }

    new Comment(commentObj).save().then(async commentFile=>{

        let {comment,commentedAt,children}=commentFile;

        Blog.findOneAndUpdate({_id},{$push:{"comments":commentFile._id},$inc:{"activity.total_comments":1,"activity.total_parent_comments":replying_to ? 0 :1},})//blog eka hoyal blog ake comment array akt comment format eka include kirima
        .then( blog=>{
            console.log("new comment created");
        })

        let notificationObj={
            type: replying_to ? "reply":'comment',
            blog:_id,
            notification_for:blog_author,
            user:user_id,
            comment:commentFile._id



        }

        if(replying_to){
            notificationObj.replied_on_comment=replying_to;

            await Comment.findOneAndUpdate({_id:replying_to},{$push :{children :commentFile._id }})
            .then(replyingToCommentDoc =>{
                 notificationObj.notification_for=replyingToCommentDoc.commented_by
            })

            
        }
        new Notification(notificationObj).save().then(notification=>{
            console.log('new notification crated');
        })

        return res.status(200).json({
            comment,commentedAt,_id:commentFile._id,user_id,children
        })
    })

    

})


server.post("/get-blog-comments",(req,res)=>{

    let {blog_id,skip}=req.body;

    let maxLimit=5;

    Comment.find({blog_id,isReply:false})
    .populate("commented_by"," personal_info.profile_img personal_info.username personal_info.fullname ")
    .skip(skip)
    .limit(maxLimit)
    .sort({
        'commentedAt':-1
    })
    .then(comment=>{
        return res.status(200).json(comment);
    })
    .catch(err=>{
        console.log(err.message);
        return res.status(500).json({error:err.message})
    })
})

server.post("/get-replies",(req,res)=>{

    let {_id,skip}=req.body;

    let maxLimit=5;

    Comment.findOne({_id})
    .populate({
        path:"children",
        options:{
            limit:maxLimit,
            skip:skip,
            sort:{'commentedAt':-1}
        },
        populate:{
            path:"commented_by",
            select:"personal_info.profile_img personal_info.username personal_info.fullname"

        },
        select:"-blog_id -updatedAt"

        
    })
    .select("children")
    .then(doc=>{
        return res.status(200).json({replies:doc.children});
    })
    .catch(err=>{
        return res.status(500).json({replies:err.message})
    })
})

const deleteComment=(_id)=>{

    Comment.findOneAndDelete({_id})
    .then(comment=>{

        if(comment.parent){
            Comment.findOneAndUpdate({_id:comment.parent},{$pull:{children:_id}})
            .then(data=>console.log('comment delete from parent'))
            .catch(err=>console.log(err))
        }

        Notification.findOneAndDelete({comment:_id}).then(notification =>console.log("comment notification deleted"));

        Notification.findOneAndDelete({reply:_id}).then(notification=>console.log("reply notification deleted"));

        Blog.findOneAndUpdate({_id:comment.blog_id},{$pull:{comments:_id},$inc:{"activity.total_comments":-1},"activity.total_parent_comments":comment.parent ?0:-1})
        .then(blog=>{
            if(comment.children.length){
                comment.children.map(replies=>{
                    deleteComment(replies)
                })
            }
        })
    })
    .catch(err=>{
        console.log(err.message);
    })
}

server.post("/delete-comment",verifyJWT,(req,res)=>{

      let user_id=req.user;

      let {_id}=req.body;

      Comment.findOne({_id})
      .then(comment=>{

         if(user_id==comment.commented_by || user_id==comment.blog_author){
            
            deleteComment(_id);
            return res.status(200).json({"status":"done"});

         }else{

            return res.status(403).json({"error":"You can not delete this comment"});

         }
      })

})





server.get("/new-notification",verifyJWT,(req,res)=>{

    let user_id=req.user;

    Notification.exists({notification_for:user_id, seen:false, user:{$ne:user_id}})
    .then(result =>{
        if(result){
            return res.status(200).json({new_Notification_available:true})
        }
        else{
            return res.status(200).json({new_Notification_available:false})
        }
       
    })
    .catch(err=>{
        console.log(err.message)
        return res.status(500).json({error:err.message})
    })
    
})

server.post("/notifications",verifyJWT,(req,res)=>{

    let user_id=req.user;
    let {page,filter,deletedDocCount}=req.body;

    let maxLimit=10;

    let findQuery={notification_for:user_id,user:{$ne:user_id}};

    let skipDocs=(page -1)*maxLimit;

    if(filter!=='all'){

        findQuery.type=filter;
    }
    if(deletedDocCount){
        skipDocs-=deletedDocCount;
    }

    Notification.find(findQuery)
    .skip(skipDocs)
    .limit(maxLimit)
    .populate("blog","title blog_id")
    .populate("user"," personal_info.profile_img personal_info.username personal_info.fullname ")
    .populate("comment","comment")
    .populate("replied_on_comment","comment")
    .populate("reply","comment")
    .sort({createdAt :-1})
    .select("createdAt type seen reply")
    .then(notifications =>{
        return res.status(200).json({notifications});
    })
    .catch(err=>{
        console.log(err.message)
        return res.status(500).json({error:err.message})
    })
    



})
server.post("/all-notifications-count",verifyJWT,(req,res)=>{

    let user_id=req.user;
    let {filter}=req.body;

   

    let findQuery={notification_for:user_id,user:{$ne:user_id}};

   

    if(filter!=='all'){

        findQuery.type=filter;
    }


    Notification.countDocuments(findQuery)
    .then(count =>{
        return res.status(200).json({totalDocs:count});
    })
    .catch(err=>{
        console.log(err.message)
        return res.status(500).json({error:err.message})
    })
    



})


server.listen(PORT,()=>{
    console.log("listening on port"+PORT);
})