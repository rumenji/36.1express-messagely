// const express = require("express");
const User = require("../models/user");
const Router = require("express").Router;
const router = new Router();
const ExpressError = require("../expressError");
const jwt = require("jsonwebtoken");
const { SECRET_KEY } = require("../config");

/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/
router.post("/login", async function (req, res, next) {
    try{
        const {username, password} = req.body;
        if(!username || !password){
            throw new ExpressError("Username and password are required!", 400);
          }
        if(await User.authenticate(username, password)){
            const token = jwt.sign({username}, SECRET_KEY);
            User.updateLoginTimestamp(username);
            return res.json({token})
        }
        throw new ExpressError("Invalid username/password", 400);
    } catch(err){
        return next(err)
    }
})
    
/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */
router.post("/register", async(req, res, next) => {
    try{
        const {username, password, first_name, last_name, phone} = req.body;
        if(!username || !password){
            throw new ExpressError("Username and password are required!", 400);
          }
        const user = await User.register({username, password, first_name, last_name, phone})    
        const token = jwt.sign({username}, SECRET_KEY);
        User.updateLoginTimestamp(username);
        return res.json({token})
        
    } catch(err){
        return next(err)
    }
})

module.exports = router;