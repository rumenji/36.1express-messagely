const express = require("express");
const ExpressError = require("../expressError");
const router = new express.Router();
const {ensureLoggedIn, ensureCorrectUser} = require("../middleware/auth");
const Message = require("../models/message")
/** GET /:id - get detail of message.
 *
 * => {message: {id,
 *               body,
 *               sent_at,
 *               read_at,
 *               from_user: {username, first_name, last_name, phone},
 *               to_user: {username, first_name, last_name, phone}}
 *
 * Make sure that the currently-logged-in users is either the to or from user.
 *
 **/
router.get("/:id", ensureLoggedIn, async (req, res, next) => {
    try{
        const message = await Message.get(req.params.id);

        if(message.to_user.username !== req.user.username && message.from_user.username !== req.user.username){
            throw new ExpressError("Not allowed!", 401)
        }
        return res.json({message: message})
    } catch(err){
        return next(new ExpressError("Please login first!", 401))
    }
})

/** POST / - post message.
 *
 * {to_username, body} =>
 *   {message: {id, from_username, to_username, body, sent_at}}
 *
 **/
router.post("/", ensureLoggedIn, async (req, res, next) => {
    try{
        const {to_username, body} = req.body;
        const from_username = req.user.username
        const message = await Message.create({from_username, to_username, body});
        return res.json({message: message})
    } catch(err){
        return next(err)
    }
})

/** POST/:id/read - mark message as read:
 *
 *  => {message: {id, read_at}}
 *
 * Make sure that the only the intended recipient can mark as read.
 *
 **/
router.post("/:id/read", ensureLoggedIn, async (req, res, next) => {
    try{
        const message = await Message.get(req.params.is);
        if(message.to_user.username !== req.user.username){
            throw new ExpressError("Not allowed!", 401)
        }
        const read = await Message.markRead(req.params.id);
        return res.json({read})
    } catch(err){
        return next(err)
    }
})

module.exports = router;