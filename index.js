require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// MongoDB setup
const uri = `mongodb+srv://${process.env.DB_USER}:${
  process.env.DB_PASS
}@cluster0.sugbz4l.mongodb.net/${
  process.env.DB_NAME || 'asset_verse_db'
  }?retryWrites=true&w=majority`;

  
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// JWT Middleware
function verifyToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });

  jwt.verify(token, process.env.JWT_SECRET || 'secretkey', (err, decoded) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = decoded;
    next();
  });
}

function verifyHR(req, res, next) {
  if (req.user.role !== 'hr')
    return res.status(403).json({ message: 'HR access only' });
  next();
}

async function run() {
  try {
    await client.connect();
    const db = client.db('asset_verse_db');

    const userCol = db.collection('users');
    const assetCol = db.collection('assets');
    const requestCol = db.collection('requests');
    const assignedCol = db.collection('assignedAssets');
    const affiliationCol = db.collection('employeeAffiliations');
    const packageCol = db.collection('packages');
    const paymentCol = db.collection('payments');

    // --------------------------
    // REGISTER HR
    // --------------------------
    app.post('/register-hr', async (req, res) => {
      const { name, companyName, companyLogo, email, password, dateOfBirth } =
        req.body;
      if (
        !name ||
        !companyName ||
        !companyLogo ||
        !email ||
        !password ||
        !dateOfBirth
      )
        return res.status(400).json({ message: 'All fields required' });
      if (password.length < 6)
        return res.status(400).json({ message: 'Password min 6 chars' });

      const existing = await userCol.findOne({ email });
      if (existing)
        return res.status(400).json({ message: 'Email already registered' });

      const hashed = await bcrypt.hash(password, 10);
      const newHR = {
        name,
        companyName,
        companyLogo,
        email,
        password: hashed,
        dateOfBirth,
        role: 'hr',
        packageLimit: 5,
        currentEmployees: 0,
        subscription: 'basic',
        createdAt: new Date(),
      };

      const result = await userCol.insertOne(newHR);
      const userSafe = { ...newHR };
      delete userSafe.password;
      res
        .status(201)
        .json({
          message: 'HR registered',
          user: userSafe,
          insertedId: result.insertedId,
        });
    });

    // --------------------------
    // REGISTER EMPLOYEE
    // --------------------------
    app.post('/register-employee', async (req, res) => {
      const { name, email, password, dateOfBirth } = req.body;
      if (!name || !email || !password)
        return res
          .status(400)
          .json({ message: 'Name, email, password required' });
      if (password.length < 6)
        return res.status(400).json({ message: 'Password min 6 chars' });

      const existing = await userCol.findOne({ email });
      if (existing)
        return res.status(400).json({ message: 'Email already registered' });

      const hashed = await bcrypt.hash(password, 10);
      const newEmployee = {
        name,
        email,
        password: hashed,
        dateOfBirth: dateOfBirth || null,
        role: 'employee',
        createdAt: new Date(),
      };

      const result = await userCol.insertOne(newEmployee);
      const userSafe = { ...newEmployee };
      delete userSafe.password;
      res
        .status(201)
        .json({
          message: 'Employee registered',
          user: userSafe,
          insertedId: result.insertedId,
        });
    });

    // --------------------------
    // LOGIN
    // --------------------------
    app.post('/login', async (req, res) => {
      const { email, password } = req.body;
      if (!email || !password)
        return res.status(400).json({ message: 'Email & password required' });

      const user = await userCol.findOne({ email });
      if (!user) return res.status(404).json({ message: 'User not found' });

      const match = await bcrypt.compare(password, user.password);
      if (!match)
        return res.status(401).json({ message: 'Invalid credentials' });

      const token = jwt.sign(
        { id: user._id, email: user.email, role: user.role },
        process.env.JWT_SECRET || 'secretkey',
        { expiresIn: '1d' }
      );
      const userSafe = { ...user };
      delete userSafe.password;

      res.json({ message: 'Login success', token, user: userSafe });
    });

    // --------------------------
    // ASSETS CRUD
    // --------------------------
    app.post('/assets', verifyToken, verifyHR, async (req, res) => {
      const asset = req.body;
      if (!asset.productName || !asset.companyName || !asset.hrEmail)
        return res
          .status(400)
          .json({ message: 'productName, companyName, hrEmail required' });

      asset.availableQuantity =
        asset.availableQuantity ?? asset.productQuantity ?? 1;
      asset.createdAt = new Date();

      const result = await assetCol.insertOne(asset);
      res
        .status(201)
        .json({ message: 'Asset created', insertedId: result.insertedId });
    });

    app.get('/assets', verifyToken, async (req, res) => {
      const assets = await assetCol.find().toArray();
      res.json(assets);
    });

    app.get('/assets/:id', verifyToken, async (req, res) => {
      const asset = await assetCol.findOne({ _id: ObjectId(req.params.id) });
      if (!asset) return res.status(404).json({ message: 'Asset not found' });
      res.json(asset);
    });

    app.put('/assets/:id', verifyToken, verifyHR, async (req, res) => {
      const result = await assetCol.updateOne(
        { _id: ObjectId(req.params.id) },
        { $set: req.body }
      );
      if (result.matchedCount === 0)
        return res.status(404).json({ message: 'Asset not found' });
      res.json({ message: 'Asset updated' });
    });

    app.delete('/assets/:id', verifyToken, verifyHR, async (req, res) => {
      const result = await assetCol.deleteOne({ _id: ObjectId(req.params.id) });
      if (result.deletedCount === 0)
        return res.status(404).json({ message: 'Asset not found' });
      res.json({ message: 'Asset deleted' });
    });

    // --------------------------
    // EMPLOYEE REQUESTS
    // --------------------------
    app.post('/requests', verifyToken, async (req, res) => {
      const { employeeEmail, hrEmail, assetId, note } = req.body;
      if (!employeeEmail || !hrEmail || !assetId)
        return res
          .status(400)
          .json({ message: 'employeeEmail, hrEmail, assetId required' });

      const asset = await assetCol.findOne({ _id: ObjectId(assetId) });
      if (!asset) return res.status(404).json({ message: 'Asset not found' });

      const newRequest = {
        employeeEmail,
        hrEmail,
        assetId: ObjectId(assetId),
        note: note || '',
        status: 'pending',
        createdAt: new Date(),
      };
      const result = await requestCol.insertOne(newRequest);
      res
        .status(201)
        .json({ message: 'Request created', insertedId: result.insertedId });
    });

    app.get('/requests/:hrEmail', verifyToken, verifyHR, async (req, res) => {
      const hrEmail = req.params.hrEmail;
      const requests = await requestCol.find({ hrEmail }).toArray();
      res.json(requests);
    });

    app.put(
      '/requests/approve/:id',
      verifyToken,
      verifyHR,
      async (req, res) => {
        const reqDoc = await requestCol.findOne({
          _id: ObjectId(req.params.id),
        });
        if (!reqDoc)
          return res.status(404).json({ message: 'Request not found' });
        if (reqDoc.status !== 'pending')
          return res.status(400).json({ message: 'Already processed' });

        const asset = await assetCol.findOne({ _id: reqDoc.assetId });
        if (!asset) return res.status(404).json({ message: 'Asset not found' });
        if (asset.availableQuantity <= 0)
          return res.status(400).json({ message: 'No quantity available' });

        await requestCol.updateOne(
          { _id: reqDoc._id },
          { $set: { status: 'approved', approvedAt: new Date() } }
        );
        await assetCol.updateOne(
          { _id: reqDoc.assetId },
          { $inc: { availableQuantity: -1 } }
        );

        await assignedCol.insertOne({
          employeeEmail: reqDoc.employeeEmail,
          hrEmail: reqDoc.hrEmail,
          assetId: reqDoc.assetId,
          status: 'assigned',
          assignedAt: new Date(),
        });

        // auto affiliation
        const aff = await affiliationCol.findOne({
          employeeEmail: reqDoc.employeeEmail,
          hrEmail: reqDoc.hrEmail,
        });
        if (!aff) {
          await affiliationCol.insertOne({
            employeeEmail: reqDoc.employeeEmail,
            hrEmail: reqDoc.hrEmail,
            status: 'active',
            affiliationDate: new Date(),
          });
          await userCol.updateOne(
            { email: reqDoc.hrEmail },
            { $inc: { currentEmployees: 1 } }
          );
        }

        res.json({ message: 'Request approved and assigned' });
      }
    );

    app.put('/requests/reject/:id', verifyToken, verifyHR, async (req, res) => {
      await requestCol.updateOne(
        { _id: ObjectId(req.params.id) },
        { $set: { status: 'rejected', rejectedAt: new Date() } }
      );
      res.json({ message: 'Request rejected' });
    });

    // --------------------------
    // ASSIGNED ASSETS (employee)
    // --------------------------
    app.get(
      '/assigned-assets/:employeeEmail',
      verifyToken,
      async (req, res) => {
        const assigned = await assignedCol
          .find({ employeeEmail: req.params.employeeEmail })
          .toArray();
        res.json(assigned);
      }
    );

    app.put('/assigned-assets/return/:id', verifyToken, async (req, res) => {
      const assignedDoc = await assignedCol.findOne({
        _id: ObjectId(req.params.id),
      });
      if (!assignedDoc)
        return res.status(404).json({ message: 'Assigned record not found' });

      if (assignedDoc.status === 'returned')
        return res.status(400).json({ message: 'Already returned' });

      await assignedCol.updateOne(
        { _id: assignedDoc._id },
        { $set: { status: 'returned', returnDate: new Date() } }
      );
      await assetCol.updateOne(
        { _id: assignedDoc.assetId },
        { $inc: { availableQuantity: 1 } }
      );

      await requestCol.updateMany(
        {
          employeeEmail: assignedDoc.employeeEmail,
          assetId: assignedDoc.assetId,
          status: 'approved',
        },
        { $set: { status: 'returned' } }
      );

      res.json({ message: 'Asset returned successfully' });
    });

    // packages
    app.get('/packages', async(req, res) => {
      const result = await packageCol.find().toArray();
      res.send(result);
    })

    app.post('/packages', async (req, res) => {
      try {
        const { name, employeeLimit, price, features } = req.body;

        if (!name || !employeeLimit || !price || !features) {
          return res.status(400).json({ message: 'All fields are required' });
        }

        const newPackage = {
          name,
          employeeLimit,
          price,
          features, // expects an array
          createdAt: new Date(),
        };

        const result = await packageCol.insertOne(newPackage);
        res
          .status(201)
          .json({
            message: 'Package added',
            insertedId: result.insertedId,
            package: newPackage,
          });
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
      }
    });



    
    // root
    app.get('/', (req, res) =>
      res.send('AssetVerse backend running')
    );

    await client.db('admin').command({ ping: 1 });
    console.log('MongoDB Connected. Backend ready.');
  } catch (err) {
    console.error(err);
  }
}

run().catch(console.dir);

app.listen(port, () => console.log(`Server running on port ${port}`));
