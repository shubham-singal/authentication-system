function requireAuth(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        res.status(401).send('You must be logged in');
    }
}


module.exports = requireAuth;