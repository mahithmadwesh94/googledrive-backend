const express = require('express')
const cors = require('cors');

require('dotenv').config();

const app = express();
const port = process.env.PORT || 8080;

app.use(cors());
app.use(express.json());

const userRouter = require('./routes/User');

app.use('/user', userRouter);

app.listen(port, () => {
    console.log(`Server is listening on ${port}`)
})



