const express = require('express');
require('dotenv').config();

const cors = require('cors');

const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');

const app = express();

app.set('trust proxy', 1);

app.use(cors({
  origin: process.env.CLIENT_URL,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(cookieParser());
app.use(bodyParser.json({ limit: '10mb' }));

require('./routes')(app); 

app.get('/', (req, res) => res.send('Server is running!'));

const PORT = process.env.SERVER_PORT;
app.listen(PORT, "0.0.0.0", () => console.log(`Server running on port ${PORT}`));