module.exports = (app) => {
    require('./api/auth/oauth/login')(app);
    require('./api/auth/oauth/callback')(app);
    require('./api/auth/custom/signup')(app);
    require('./api/auth/custom/login')(app);
    require('./api/auth/custom/verify')(app);

    require('./api/getuserprofile')(app);

    require('./api/auth/checkauth')(app);
    require('./api/auth/updatetokens')(app);
    require('./api/auth/logout')(app);
};