require("dotenv").config();

const { connect } = require("@tursodatabase/serverless");


const db = connect({
    url: process.env.TURSO_DATABASE_URL,
    authToken: process.env.TURSO_AUTH_TOKEN
});


module.exports = db;
