/** User class for message.ly */
const { BCRYPT_WORK_FACTOR } = require("../config");
const db = require("../db");
const ExpressError = require("../expressError");
const bcrypt = require("bcrypt");

/** User of the site. */

class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({username, password, first_name, last_name, phone}) { 
    try{
      const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
      const results = await db.query(`INSERT INTO users 
                                    (username, password, first_name, last_name, phone, join_at, last_login_at)
                                    VALUES($1, $2, $3, $4, $5, current_timestamp, current_timestamp)
                                    RETURNING username, password, first_name, last_name, phone`,
                                    [username, hashedPassword, first_name, last_name, phone])
      return results.rows[0]                        
    } catch(err) {
      if(err.code === '23505'){
        throw new ExpressError('Username already taken!', 400)
      }
      throw new ExpressError(err)
    }
  }
  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) { 
    try{
      const results = await db.query(`SELECT username, password FROM users
                                      WHERE username = $1`, [username])
      const user = results.rows[0];
      if(user){
        if(await bcrypt.compare(password, user.password)){
          return true
        }
        return false
      }
      return false
      
    } catch(err) {
      throw new ExpressError(err, 400)
    }
  }
  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    try{
      const user = await db.query(`UPDATE users SET last_login_at=current_timestamp WHERE username = $1 RETURNING username`, [username]);
      if(user.rows[0] === 0){
        throw new ExpressError("Username not found", 400)
      }
    } catch(err){
      throw new ExpressError(err, 400)
    }
   }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() { 
    const results = await db.query(`SELECT username, first_name, last_name, phone FROM users`);
    return results.rows
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) { 
    const results = await db.query(`SELECT username, first_name, last_name, phone, join_at, last_login_at FROM users WHERE username=$1`, [username]);
    if(results.rows[0] === 0){
      throw new ExpressError("Username not found", 400)
    }
    return results.rows[0]
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    const messages = await db.query(`SELECT m.id, m.to_username, m.body, m.sent_at, m.read_at, u.username, u.first_name, u.last_name, u.phone 
                                    FROM messages AS m
                                    INNER JOIN users AS u ON (m.to_username = u.username)
                                    WHERE from_username=$1`, [username]);
    
    return messages.rows.map(m => ({
        id: m.id,
        to_user: {
          username: m.username,
          first_name: m.first_name,
          last_name: m.last_name,
          phone: m.phone
        },
        body: m.body,
        sent_at: m.sent_at,
        read_at: m.read_at
      }))
    }
   

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    const messages = await db.query(`SELECT m.id, m.from_username, m.body, m.sent_at, m.read_at, u.username, u.first_name, u.last_name, u.phone 
                                    FROM messages AS m
                                    INNER JOIN users AS u ON (m.from_username = u.username)
                                    WHERE to_username=$1`, [username]);
   
    return messages.rows.map(m => ({
        id: m.id,
        from_user: {
          username: m.username,
          first_name: m.first_name,
          last_name: m.last_name,
          phone: m.phone
        },
        body: m.body,
        sent_at: m.sent_at,
        read_at: m.read_at
      }))
    }
  }

module.exports = User;