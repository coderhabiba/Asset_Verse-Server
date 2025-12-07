const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion } = require('mongodb');
const app = express();
const port = process.env.PORT || 3000;
import dotenv from 'dotenv';
dotenv.config();

// middleware
app.use(express.json())
app.use(cors())

// uri
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.sugbz4l.mongodb.net/?appName=Cluster0`;

// Create a MongoClient
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});


async function run() {
  try {
    await client.connect();
    
    // database create and create collections
    const db = client.db('asset_verse_db');
    const userCollection = db.collection('users');
    const assetCollection = db.collection('assets');
    const requestCollection = db.collection('requests');
    const employeeAffiliationCollection = db.collection('employeeAffiliations');
    const packageCollection = db.collection('packages');
    
    
    app.get('/assets', async (req,res) => {
      
    })

    app.post('/assets', async(req,res) => {
      const asset = req.body;
      
    })

    await client.db('admin').command({ ping: 1 });
    console.log(
      'Pinged your deployment. You successfully connected to MongoDB!'
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);


app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
