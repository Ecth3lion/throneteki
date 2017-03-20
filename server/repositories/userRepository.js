const mongoskin = require('mongoskin');
const users = db.get('users');
const escapeRegex = require('../util.js').escapeRegex;

class UserRepository {
    constructor(dbPath) {
        this.db = mongoskin.db(dbPath);
    }

    callCallbackIfPresent(callback, ...params) {
        if(!callback) {
            return;
        }

        callback(...params);
    }

    getUserByUsername(username, callback) {
        db.collection('users').find({ username: {'$regex': new RegExp('^' + escapeRegex(username.toLowerCase()) + '$', 'i') }}).toArray((err, users) => {
            if(err) {
                logger.error(err);

                this.callCallbackIfPresent(callback, err);

                return;
            } 
            
            this.callCallbackIfPresent(callback, err, users[0]);
        });
    }

    getUserById(id, callback) {
        db.collection('users').find({ _id: mongoskin.helper.toObjectID(id) }).toArray((err, users => {
            if(err) {
                logger.error(err);

                this.callCallbackIfPresent(callback, err);

                return;
            }

            this.callCallbackIfPresent(err, users);
        }));
    }

    addUser(user, callback) {
        db.collection('users').insert(user, (err, result) => {
            if(err) {
                logger.info(err);
                this.callCallbackIfPresent(callback, err);

                return;
            }

            this.callCallbackIfPresent(callback, result);
        })
        return users.insert(user);
    }

    setResetToken(user, token, tokenExpiration) {
        return users.update({ username: user.username }, { '$set': { resetToken: token, tokenExpires: tokenExpiration } });
    }

    setPassword(user, password) {
        return users.update({ username: user.username }, { '$set': { password: password } });
    }

    clearResetToken(user) {
        return users.update({ username: user.username }, { '$set': { resetToken: undefined, tokenExpires: undefined } });
    }
}

module.exports = UserRepository;
