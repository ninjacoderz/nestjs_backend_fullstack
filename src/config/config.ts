export default () => ({
    database: {
        connectionString: process.env.CONNECTION_STRING
    },
    jwt: {
        secret: process.env.JWT_SECRET
    }
})