const express = require('express');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
require('dotenv').config();
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const app = express();
const port = process.env.PORT || 5000;

// middleware
app.use(
  cors({
    origin: ['http://localhost:5173'],
    credentials: true,
  })
);
app.use(express.json());


const uri = process.env.MONGODB_URI;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});


async function run() {
  try {
    // await client.connect();

    const db = client.db('asset_verse_db');
    const users = db.collection('users');
    const assets = db.collection('assets');
    const requests = db.collection('requests');
    const assigned = db.collection('assigned');
    const affiliations = db.collection('affiliations');
    const payments = db.collection('payments');
    const packages = db.collection('packages');

    // JWT verification middleware
    const verifyToken = (req, res, next) => {
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        return res
          .status(401)
          .send({ message: 'Unauthorized access: No token provided' });
      }
      const token = authHeader.split(' ')[1];
      jwt.verify(
        token,
        process.env.JWT_SECRET,
        (err, decoded) => {
          if (err) {
            return res
              .status(401)
              .send({ message: 'Unauthorized access: Invalid token' });
          }
          req.user = decoded;
          next();
        }
      );
    };

    // role verification middleware
    const verifyHR = (req, res, next) => {
      if (req.user.role !== 'hr') {
        return res
          .status(403)
          .send({ message: 'Forbidden access: HR role required' });
      }
      next();
    };

    /*=============
      user routes
    ===============*/

    // register HR
    app.post('/register-hr',  async (req, res) => {
      try {
        const { name, companyName, companyLogo, email, password, date } =
          req.body;

        if (
          !name ||
          !companyName ||
          !companyLogo ||
          !email ||
          !password ||
          !date
        )
          return res.status(400).json({ message: 'All fields required' });

        if (password.length < 6)
          return res
            .status(400)
            .json({ message: 'Password must be >= 6 chars' });

        const exists = await users.findOne({ email });
        if (exists)
          return res.status(400).json({ message: 'Email already registered' });

        const hashed = await bcrypt.hash(password, 10);

        const newHR = {
          name,
          companyName,
          companyLogo,
          email,
          password: hashed,
          date,
          role: 'hr',
          packageLimit: 5,
          currentEmployees: 0,
          subscription: 'basic',
          createdAt: new Date(),
        };

        const result = await users.insertOne(newHR);
        const token = jwt.sign(
          { email: email },
          process.env.JWT_SECRET
        );
        const safe = { ...newHR };
        delete safe.password;
        safe._id = result.insertedId.toString();

        res.status(201).json({ message: 'HR registered', token, user: safe });
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
      }
    });

    // register employee
    app.post('/register-employee', async (req, res) => {
      try {
        const { name, email, password, date, profileImage, hrEmail } =
          req.body;
        if (!name || !email || !password) {
          return res
            .status(400)
            .json({ message: 'Name, email, and password are required.' });
        }
        if (password.length < 6) {
          return res
            .status(400)
            .json({ message: 'Password must be at least 6 characters long.' });
        }

        const normalizedEmail = email.toLowerCase().trim();

        const exists = await users.findOne({ email: normalizedEmail });
        if (exists) {
          return res.status(400).json({ message: 'Email already registered.' });
        }

        const hashed = await bcrypt.hash(password, 10);

        const newEmployee = {
          name,
          email: normalizedEmail,
          password: hashed,
          date: date || dateOfBirth,
          profileImage: profileImage || null,
          role: 'employee',
          hrEmail: hrEmail || null,
          status: hrEmail ? 'affiliated' : 'unaffiliated',
          createdAt: new Date(),
          affiliationDate: null,
        };

        const result = await users.insertOne(newEmployee);
        const { password: _, ...safeUser } = newEmployee;
        safeUser._id = result.insertedId.toString();
        const token = jwt.sign(
          { email: newEmployee.email },
          process.env.JWT_SECRET
        );
        res.status(201).json({
          message: 'Employee registered successfully',
          insertedId: result.insertedId.toString(),
          token,
          user: safeUser,
        });
      } catch (err) {
        console.error('Registration Error:', err);
        res.status(500).json({ message: 'Internal Server error' });
      }
    });

    // login
    app.post('/login', async (req, res) => {
      try {
        const { email, password } = req.body;
        if (!email || !password)
          return res.status(400).json({ message: 'Email & password required' });

        const user = await users.findOne({ email });
        if (!user) return res.status(404).json({ message: 'User not found' });

        const match = await bcrypt.compare(password, user.password);
        if (!match)
          return res.status(401).json({ message: 'Invalid credentials' });

        const token = jwt.sign(
          { id: user._id.toString(), email: user.email, role: user.role },
          process.env.JWT_SECRET || 'secretkey',
          { expiresIn: '1d' }
        );

        const safeUser = { ...user };
        delete safeUser.password;
        if (safeUser._id) safeUser._id = safeUser._id.toString();

        res.json({ message: 'Login success', token, user: safeUser });
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
      }
    });

    // get user by email
    app.get('/user/:email', verifyToken, async (req, res) => {
      try {
        const email = req.params.email;

        if (req.user.email !== email) {
          return res.status(403).json({ message: 'Forbidden access' });
        }

        const user = await users.findOne({ email });
        if (!user) return res.status(404).json({ message: 'User not found' });

        const safe = { ...user };
        delete safe.password;
        if (safe._id) safe._id = safe._id.toString();

        res.json(safe);
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
      }
    });

    // get employee info by hr
    app.get('/hr/stats/:hrEmail', verifyToken, async (req, res) => {
      try {
        const hrEmail = req.params.hrEmail;
        if (req.user.email !== hrEmail) {
          return res.status(403).json({ message: 'Forbidden access' });
        }
        const hrUser = await users.findOne({ email: hrEmail });
        if (!hrUser || hrUser.role !== 'hr') {
          return res.status(404).json({ message: 'HR User not found' });
        }
        const packageLimit = hrUser.packageLimit || 5;
        const employeeCount = await users.countDocuments({
          hrEmail: hrEmail,
          role: 'employee',
        });

        res.json({
          hrEmail: hrEmail,
          packageLimit: packageLimit,
          currentEmployees: employeeCount,
        });
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
      }
    });

    // update employee profile
    app.put('/user/:email', verifyToken, async (req, res) => {
      const email = req.params.email;

      if (req.user.email !== email) {
        return res.status(403).send({ message: 'Forbidden access' });
      }

      const { name, photo, dateOfBirth } = req.body;
      const update = {};

      if (name) update.name = name;
      if (photo) update.profileImage = photo;
      if (dateOfBirth) update.dateOfBirth = dateOfBirth;

      if (Object.keys(update).length === 0) {
        return res.status(400).send({ message: 'Nothing to update' });
      }

      try {
        const result = await users.updateOne({ email }, { $set: update });

        if (result.matchedCount === 0) {
          return res.status(404).send({ message: 'User not found' });
        }

        const updatedUser = await users.findOne({ email });
        delete updatedUser.password;
        if (updatedUser._id) updatedUser._id = updatedUser._id.toString();

        res.send({
          success: true,
          message: 'Profile updated successfully',
          user: updatedUser,
        });
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: 'Profile update failed' });
      }
    });

    /*===================
        assets hr
    ===================== */

    // create asset (HR only)
    app.post('/assets', verifyToken, verifyHR, async (req, res) => {
      try {
        const { name, image, type, quantity } = req.body;

        if (!name)
          return res.status(400).json({ message: 'Asset Name required' });

        const hrEmail = req.user.email;

        const hrUser = await users.findOne({ email: hrEmail });
        if (!hrUser) {
          return res.status(404).json({ message: 'HR not found' });
        }

        const qty = quantity ? Number(quantity) : 1;

        const asset = {
          name,
          image: image || null,
          type: type || 'Returnable',
          quantity: qty,
          availableQuantity: qty,
          hrEmail,
          companyName: hrUser.companyName,
          dateAdded: new Date(),
        };

        const result = await assets.insertOne(asset);
        res.status(201).json({
          message: 'Asset created',
          insertedId: result.insertedId.toString(),
        });
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
      }
    });

    // GET assets in hr dashboard
    app.get('/assets', verifyToken, verifyHR, async (req, res) => {
      try {
        const hrEmail = req.user.email;
        let { page = 1, limit = 10, search = '' } = req.query; 

        page = parseInt(page);
        limit = parseInt(limit);

        const filter = { hrEmail };

        if (search) {
          filter.name = { $regex: search, $options: 'i' };
        }

        const skip = (page - 1) * limit;

        const total = await assets.countDocuments(filter);
        const assetDocs = await assets
          .find(filter)
          .sort({ dateAdded: -1 })
          .skip(skip)
          .limit(limit)
          .toArray();

        res.json({
          total,
          page,
          limit,
          assets: assetDocs,
        });
      } catch (error) {
        console.error('ASSET ERROR:', error);
        res.status(500).json({ message: 'Internal Server Error' });
      }
    });

    // asset for employee
    app.get('/assets/available', verifyToken, async (req, res) => {
      try {
        const assetDocs = await assets
          .find({ availableQuantity: { $gt: 0 } })
          .toArray();

        const safeAssets = assetDocs.map(a => ({
          _id: a._id.toString(),
          name: a.name,
          type: a.type,
          availableQuantity: a.availableQuantity,
          hrEmail: a.hrEmail,
          companyName: a.companyName,
          image: a.image || null,
        }));
        res.json(safeAssets);
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
      }
    });

    // get single asset
    app.get('/assets/:id', verifyToken, async (req, res) => {
      try {
        const idString = req.params.id;
        let id;
        try {
          id = new ObjectId(idString);
        } catch (e) {
          return res.status(400).json({ message: 'Invalid asset id format' });
        }

        const a = await assets.findOne({ _id: id });
        if (!a) return res.status(404).json({ message: 'Asset not found' });
        a._id = a._id.toString();
        res.json(a);
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
      }
    });

    // update asset
    app.patch('/assets/:id', verifyToken, verifyHR, async (req, res) => {
      try {
        const idString = req.params.id;
        let id;
        try {
          id = new ObjectId(idString);
        } catch (e) {
          return res.status(400).json({ message: 'Invalid asset id format' });
        }

        const { name, image, type, quantity } = req.body;
        const update = {};

        if (name) update.name = name;
        if (image) update.image = image;
        if (type) update.type = type;

        if (quantity !== undefined) {
          const qty = Number(quantity);
          update.quantity = qty;
          update.availableQuantity = qty;
        }
        update.updatedAt = new Date();

        const result = await assets.updateOne({ _id: id }, { $set: update });
        if (result.matchedCount === 0)
          return res.status(404).json({ message: 'Asset not found' });

        res.json({ message: 'Asset updated' });
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
      }
    });

    // delete asset
    app.delete('/assets/:id', verifyToken, verifyHR, async (req, res) => {
      try {
        const idString = req.params.id;
        let id;
        try {
          id = new ObjectId(idString);
        } catch (e) {
          return res.status(400).json({ message: 'Invalid asset id format' });
        }

        const result = await assets.deleteOne({ _id: id });
        if (result.deletedCount === 0)
          return res.status(404).json({ message: 'Asset not found' });
        res.json({ message: 'Asset deleted' });
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
      }
    });

    /* ===================
      req (employee to HR)
    ====================== */

    // create request (employee)
    app.post('/requests', verifyToken, async (req, res) => {
      try {
        const { employeeEmail, assetId, note } = req.body; // ফ্রন্টএন্ড থেকে শুধু এই ৩টি পাঠালেই হবে

        if (!employeeEmail || !assetId) {
          return res.status(400).json({
            message: 'Employee Email and Asset ID are required.',
          });
        }

        const assetOid = new ObjectId(assetId);
        const assetDoc = await assets.findOne({ _id: assetOid });

        if (!assetDoc) {
          return res.status(404).json({ message: 'Asset not found.' });
        }

        const employeeUser = await users.findOne({ email: employeeEmail });
        const newReq = {
          employeeEmail: employeeEmail,
          hrEmail: assetDoc.hrEmail,
          assetId: assetOid.toString(),
          assetName: assetDoc.name || 'N/A',
          assetType: assetDoc.type || 'N/A',
          requesterName: employeeUser ? employeeUser.name : 'Unknown Requester',
          requestDate: new Date(),
          approvalDate: null,
          requestStatus: 'pending',
          note: note || '',
        };

        const result = await requests.insertOne(newReq);

        res.status(201).json({
          message: 'Asset request created successfully.',
          insertedId: result.insertedId.toString(),
        });
      } catch (err) {
        console.error('Error creating request:', err);
        res.status(500).json({
          message: 'Internal server error.',
        });
      }
    });

    // GET employee sees own requests
    app.get('/requests/employee/:email', verifyToken, async (req, res) => {
      try {
        const email = req.params.email.trim();
        const docs = await requests
          .find({
            employeeEmail: { $regex: new RegExp(`^${email}$`, 'i') },
          })
          .toArray();
        if (!docs || docs.length === 0) return res.json([]);
        const finalRequests = await Promise.all(
          docs.map(async request => {
            let assetDetails = null;
            if (request.assetId) {
              try {
                assetDetails = await assets.findOne({
                  _id: new ObjectId(request.assetId),
                });
              } catch (e) {
                console.error('Invalid Asset ID');
              }
            }

            return {
              ...request,
              _id: request._id.toString(),
              assetName:
                assetDetails?.name || request.assetName || 'Unknown Asset',
              assetType: assetDetails?.type || request.assetType || 'N/A',
              requestDate: request.requestDate,
              requestStatus: request.requestStatus || 'pending',
              note: request.note || '',
            };
          })
        );

        res.json(finalRequests);
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
      }
    });

    // get requests for an HR
    app.get('/requests/:hrEmail', verifyToken, verifyHR, async (req, res) => {
      try {
        const hrEmail = req.params.hrEmail;
        const docs = await requests.find({ hrEmail }).toArray();
        const safe = await Promise.all(
          docs.map(async r => {
            let assetDoc = null;
            if (r.assetId) {
              try {
                assetDoc = await assets.findOne({
                  _id: new ObjectId(r.assetId),
                });
              } catch (e) {
                /* handle invalid ID silently */
              }
            }

            const emp = await users.findOne(
              { email: r.employeeEmail },
              { projection: { password: 0 } }
            );
            return {
              ...r,
              _id: r._id.toString(),
              asset: assetDoc
                ? { ...assetDoc, _id: assetDoc._id.toString() }
                : null,
              employee: emp ? { ...emp, _id: emp._id.toString() } : null,
            };
          })
        );
        res.json(safe);
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
      }
    });

    // approve request
    app.put(
      '/requests/approve/:id',
      verifyToken,
      verifyHR,
      async (req, res) => {
        try {
          const requestId = req.params.id;
          const hrEmail = req.user.email;

          const request = await requests.findOne({
            _id: new ObjectId(requestId),
          });

          if (!request)
            return res.status(404).json({ message: 'Request not found' });

          if (
            request.requestStatus === 'approved' ||
            request.requestStatus === 'rejected'
          ) {
            return res
              .status(400)
              .json({ message: 'Request already processed' });
          }

          const employeeEmail = request.employeeEmail;
          const assetOid = new ObjectId(request.assetId);

          const hrUser = await users.findOne({ email: hrEmail });
          const assetDoc = await assets.findOne({ _id: assetOid });

          const employeeDoc = await users.findOne({
            email: employeeEmail,
            role: 'employee',
          });

          if (!hrUser || !assetDoc)
            return res.status(404).json({ message: 'HR or Asset not found' });

          if ((assetDoc.availableQuantity || 0) <= 0) {
            return res.status(400).json({ message: 'Asset is out of stock!' });
          }

          const willIncrement = !employeeDoc || employeeDoc.hrEmail !== hrEmail;
          const actualAffiliatedCount = await users.countDocuments({
            hrEmail: hrEmail,
            role: 'employee',
          });
          const limit = hrUser.packageLimit || 5;

          if (willIncrement && actualAffiliatedCount >= limit) {
            return res.status(400).json({
              code: 'PACKAGE_LIMIT_EXCEEDED',
              message: `Limit exceeded. You have ${actualAffiliatedCount} members, maximum ${limit} allowed.`,
            });
          }

          await requests.updateOne(
            { _id: new ObjectId(requestId) },
            {
              $set: {
                requestStatus: 'approved', 
                approvalDate: new Date(),
                processedBy: hrEmail,
              },
            }
          );

          await assets.updateOne(
            { _id: assetOid },
            { $inc: { availableQuantity: -1 } }
          );

          const assignedDoc = {
            assetId: request.assetId,
            assetName: request.assetName || assetDoc.name,
            assetImage: assetDoc.image || null,
            assetType: assetDoc.type || null,
            employeeEmail: employeeEmail,
            employeeName:
              request.requesterName || employeeDoc?.name || 'Unknown',
            hrEmail: hrEmail,
            companyName: hrUser.companyName || assetDoc.companyName || null,
            assignmentDate: new Date(),
            status: 'assigned',
          };
          await assigned.insertOne(assignedDoc);

          if (willIncrement && employeeEmail) {
            await users.updateOne(
              { email: employeeEmail, role: 'employee' },
              {
                $set: {
                  hrEmail: hrEmail,
                  status: 'affiliated',
                  affiliationDate: new Date(),
                },
              }
            );

            await affiliations.insertOne({
              employeeEmail: employeeEmail,
              employeeName:
                employeeDoc?.name || request.requesterName || 'Unknown',
              hrEmail: hrEmail,
              companyName: hrUser.companyName,
              affiliationDate: new Date(),
              status: 'active',
            });

            await users.updateOne(
              { email: hrEmail },
              { $inc: { currentEmployees: 1 } }
            );
          }

          res.json({
            message: 'Approved and assigned successfully!',
            modifiedCount: 1,
          });
        } catch (err) {
          console.error(err);
          res.status(500).json({ message: 'Server error' });
        }
      }
    );

    // reject request
    app.put('/requests/reject/:id', verifyToken, verifyHR, async (req, res) => {
      try {
        const reqIdString = req.params.id;
        let reqId;
        try {
          reqId = new ObjectId(reqIdString);
        } catch (e) {
          return res
            .status(400)
            .json({ message: 'Invalid Request ID format.' });
        }

        const r = await requests.findOne({ _id: reqId });
        if (!r) return res.status(404).json({ message: 'Request not found' });
        if (r.requestStatus !== 'pending')
          return res.status(400).json({ message: 'Already processed' });

        await requests.updateOne(
          { _id: reqId },
          {
            $set: {
              requestStatus: 'rejected',
              rejectedAt: new Date(),
              processedBy: req.user.email || null,
            },
          }
        );
        res.json({ message: 'Request rejected' });
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
      }
    });

    /*===========================
      assigned assets (employee)
    ============================= */
    // get assigned assets for employee
    app.get(
      '/assigned-assets/:employeeEmail',
      verifyToken,
      async (req, res) => {
        try {
          const employeeEmail = req.params.employeeEmail;
          const assignedRequests = await assigned
            .find({
              employeeEmail: employeeEmail,
              status: 'assigned',
            })
            .toArray();

          if (assignedRequests.length === 0) {
            return res.json([]);
          }
          const finalAssets = await Promise.all(
            assignedRequests.map(async request => {
              let assetDetails = null;
              if (request.assetId) {
                try {
                  const assetObjectId = new ObjectId(request.assetId);
                  assetDetails = await assets.findOne({
                    _id: assetObjectId,
                  });
                } catch (e) {
                  console.error(
                    `Invalid ObjectId for assetId: ${request.assetId}`
                  );
                }
              }
              return {
                _id: request._id.toString(),
                name: assetDetails ? assetDetails.name : 'Unknown Asset',
                assetType: assetDetails ? assetDetails.type : 'N/A',
                assetImage: assetDetails ? assetDetails.image : null,
                companyName: request.companyName || 'N/A',
                assignmentDate: request.assignmentDate,
                status: request.status,
                assetId: request.assetId,
                returnDate: request.returnDate,
                hrEmail: request.hrEmail,
              };
            })
          );

          res.json(finalAssets);
        } catch (err) {
          console.error('Error fetching assigned assets:', err);
          res.status(500).json({
            message: 'Server error occurred while fetching assigned assets',
          });
        }
      }
    );

    // return assigned asset by assigned id
    app.put('/assigned-assets/return/:id', verifyToken, async (req, res) => {
      try {
        const idString = req.params.id;
        let id;
        try {
          id = new ObjectId(idString);
        } catch (e) {
          return res
            .status(400)
            .json({ message: 'Invalid assigned record id format.' });
        }

        const doc = await assigned.findOne({ _id: id });
        if (!doc)
          return res.status(404).json({ message: 'Assigned record not found' });
        if (doc.status === 'returned')
          return res.status(400).json({ message: 'Already returned' });

        await assigned.updateOne(
          { _id: id },
          { $set: { status: 'returned', returnDate: new Date() } }
        );

        let assetOid;
        try {
          assetOid = new ObjectId(doc.assetId);
        } catch (e) {
          return res.status(500).json({
            message:
              'Internal Error: Invalid Asset ID format in assigned record.',
          });
        }

        await assets.updateOne(
          { _id: assetOid },
          { $inc: { availableQuantity: 1 } }
        );

        await requests.updateMany(
          {
            employeeEmail: doc.employeeEmail,
            assetId: doc.assetId,
            requestStatus: 'approved',
          },
          { $set: { requestStatus: 'returned', returnedAt: new Date() } }
        );

        res.json({ message: 'Asset returned successfully' });
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
      }
    });

    /*====================
      employee management
    ======================*/
    // get employees affiliated for HR
    app.get('/employees/:hrEmail', verifyToken, verifyHR, async (req, res) => {
      try {
        const hrEmail = req.params.hrEmail;
        // find affiliations active
        const affs = await affiliations
          .find({ hrEmail, status: 'active' })
          .toArray();
        const populated = await Promise.all(
          affs.map(async a => {
            const emp = await users.findOne(
              { email: a.employeeEmail },
              { projection: { password: 0 } }
            );
            return {
              ...a,
              _id: a._id.toString(),
              employee: emp ? { ...emp, _id: emp._id.toString() } : null,
            };
          })
        );
        res.json(populated);
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
      }
    });

    // remove employee from company
    app.delete(
      '/employee/:affiliationId',
      verifyToken,
      verifyHR,
      async (req, res) => {
        try {
          const affIdString = req.params.affiliationId;
          let affId;
          try {
            affId = new ObjectId(affIdString);
          } catch (e) {
            return res
              .status(400)
              .json({ message: 'Invalid affiliation id format.' });
          }

          const aff = await affiliations.findOne({ _id: affId });
          if (!aff)
            return res.status(404).json({ message: 'Affiliation not found' });

          // 1. Deactivate affiliation
          await affiliations.updateOne(
            { _id: affId },
            { $set: { status: 'inactive', removedAt: new Date() } }
          );

          // 2. Decrement HR currentEmployees
          await users.updateOne(
            { email: aff.hrEmail },
            { $inc: { currentEmployees: -1 } }
          );

          // 3. Return all currently assigned assets
          const assignedDocs = await assigned
            .find({ employeeEmail: aff.employeeEmail, status: 'assigned' })
            .toArray();

          for (const a of assignedDocs) {
            await assigned.updateOne(
              { _id: a._id },
              { $set: { status: 'returned', returnedAt: new Date() } }
            );

            let assetOid;
            try {
              assetOid = new ObjectId(a.assetId);
            } catch (e) {
              console.error(
                'Invalid Asset ID in assigned record during employee removal.'
              );
              continue; // Skip asset update if ID is bad
            }

            await assets.updateOne(
              { _id: assetOid },
              { $inc: { availableQuantity: 1 } }
            );

            await requests.updateMany(
              {
                employeeEmail: aff.employeeEmail,
                assetId: a.assetId,
                requestStatus: 'approved',
              },
              { $set: { requestStatus: 'returned' } }
            );
          }

          res.json({ message: 'Employee removed and assets returned' });
        } catch (err) {
          console.error(err);
          res.status(500).json({ message: 'Server error' });
        }
      }
    );

    /*===================================
      team members in employee dashboard
     ====================================*/
    app.get('/team-members/:hrEmail', verifyToken, async (req, res) => {
      try {
        const hrEmail = req.params.hrEmail;
        const affs = await affiliations
          .find({ hrEmail, status: 'active' })
          .toArray();

        const populated = await Promise.all(
          affs.map(async a => {
            const emp = await users.findOne(
              { email: a.employeeEmail },
              {
                projection: {
                  password: 0,
                  packageLimit: 0,
                  currentEmployees: 0,
                },
              }
            );
            return {
              ...a,
              _id: a._id.toString(),
              employee: emp
                ? {
                    _id: emp._id.toString(),
                    name: emp.name,
                    email: emp.email,
                    profileImage: emp.profileImage,
                    dateOfBirth: emp.dateOfBirth,
                  }
                : null,
            };
          })
        );
        res.json(populated);
      } catch (err) {
        console.error('Error fetching team members for employee:', err);
        res.status(500).json({ message: 'Server error' });
      }
    });

    /*==================
      package & payment
      ==================*/

    // get packages
    app.get('/packages', async (req, res) => {
      try {
        const docs = await packages.find().toArray();
        res.json(docs);
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
      }
    });

    // add package (hr)
    app.post('/packages', async (req, res) => {
      try {
        const { name, employeeLimit, price, features } = req.body;
        if (!name || !employeeLimit || !price || !features)
          return res.status(400).json({ message: 'All fields required' });
        const pkg = {
          name,
          employeeLimit: Number(employeeLimit),
          price: Number(price),
          features,
          createdAt: new Date(),
        };
        const result = await packages.insertOne(pkg);
        res.status(201).json({
          message: 'Package added',
          insertedId: result.insertedId.toString(),
          package: pkg,
        });
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
      }
    }); //panding

    // create stripe payment intent
    app.post('/create-payment-intent', verifyToken, async (req, res) => {
      try {
        const { price, packageName, employeeLimit, hrEmail } = req.body;

        if (!price || !packageName || !hrEmail || !employeeLimit) {
          return res.status(400).json({ message: 'Missing payment details' });
        }

        const amountInCents = Math.round(Number(price) * 100);

        const session = await stripe.checkout.sessions.create({
          payment_method_types: ['card'],
          line_items: [
            {
              price_data: {
                currency: 'usd',
                unit_amount: amountInCents,
                product_data: {
                  name: `Upgrade: ${packageName} Package`,
                  description: `Increase limit to ${employeeLimit} employees`,
                },
              },
              quantity: 1,
            },
          ],
          mode: 'payment',
          metadata: {
            hrEmail: hrEmail,
            packageName: packageName,
            employeeLimit: String(employeeLimit),
          },
          customer_email: hrEmail,
          success_url: `${process.env.BASE_URL}/dashboard/upgrade/payment-success?session_id={CHECKOUT_SESSION_ID}`,
          cancel_url: `${process.env.SITE_DOMAIN}/hr-dashboard/upgrade?status=failed`,
        });

        res.send({ url: session.url });
      } catch (err) {
        console.error('Stripe Error:', err);
        res.status(500).json({ message: 'Stripe initiation failed' });
      }
    });

    //
    app.get('/dashboard/upgrade/payment-success', async (req, res) => {
      try {
        const sessionId = req.query.session_id;

        if (!sessionId) {
          return res.redirect(
            `${process.env.SITE_DOMAIN}/hr-dashboard/upgrade?status=error`
          );
        }

        const session = await stripe.checkout.sessions.retrieve(sessionId);

        if (session.payment_status === 'paid') {
          const { hrEmail, packageName, employeeLimit } = session.metadata;

          const isAlreadyProcessed = await payments.findOne({
            transactionId: session.payment_intent,
          });

          if (!isAlreadyProcessed) {
            await users.updateOne(
              { email: hrEmail },
              {
                $set: {
                  packageLimit: Number(employeeLimit),
                  subscription: packageName,
                  lastPaymentDate: new Date(),
                },
              }
            );

            const paymentRecord = {
              hrEmail: hrEmail,
              packageName: packageName,
              employeeLimit: Number(employeeLimit),
              amount: session.amount_total / 100,
              currency: session.currency,
              transactionId: session.payment_intent,
              paymentStatus: 'paid',
              paidAt: new Date(),
            };
            await payments.insertOne(paymentRecord);
          }

          return res.redirect(
            `${process.env.SITE_DOMAIN}/hr-dashboard/upgrade?status=success&txn=${session.payment_intent}`
          );
        } else {
          return res.redirect(
            `${process.env.SITE_DOMAIN}/hr-dashboard/upgrade?status=failed`
          );
        }
      } catch (err) {
        console.error('Payment Handler Error:', err);
        return res.redirect(
          `${process.env.SITE_DOMAIN}/hr-dashboard/upgrade?status=error`
        );
      }
    });

    // payment success client call to save payment
    app.post('/payments', verifyToken, async (req, res) => {
      try {
        const payment = req.body;
        if (!payment || !payment.hrEmail || !payment.packageName)
          return res
            .status(400)
            .json({ message: 'hrEmail & packageName required' });

        payment.paymentDate = new Date();
        const result = await payments.insertOne(payment);

        // update HR packageLimit/subscription
        await users.updateOne(
          { email: payment.hrEmail },
          {
            $set: {
              packageLimit: Number(payment.employeeLimit),
              subscription: payment.packageName,
            },
          }
        );

        res.json({
          message: 'Payment recorded',
          insertedId: result.insertedId.toString(),
        });
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
      }
    });

    // get payment history for HR (for feture update)
    app.get('/payments/:hrEmail', verifyToken, verifyHR, async (req, res) => {
      try {
        const hrEmail = req.params.hrEmail;
        const docs = await payments.find({ hrEmail }).toArray();
        res.json(docs);
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
      }
    });

    /* =====================
            analytics
        ===================== */

    // GET /analytics/:hrEmail
    app.get('/analytics/:hrEmail', verifyToken, verifyHR, async (req, res) => {
      try {
        const hrEmail = req.params.hrEmail;

        const returnableCount = await assets.countDocuments({
          hrEmail,
          type: { $regex: /^returnable$/i },
        });
        const nonReturnableCount = await assets.countDocuments({
          hrEmail,
          type: { $regex: /^non-returnable$/i },
        });

        const topRequestsData = await requests
          .aggregate([
            { $match: { hrEmail: hrEmail } },
            { $group: { _id: '$assetName', count: { $sum: 1 } } },
            { $sort: { count: -1 } },
            { $limit: 5 },
          ])
          .toArray();

        const topRequested = topRequestsData.map(item => ({
          name: item._id,
          count: item.count,
        }));

        res.json({
          returnableCount,
          nonReturnableCount,
          topRequested,
        });
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
      }
    });

    //
    app.get('/', (req, res) => {
      res.send('Asset Management Server is running!');
    });
  } finally {
    
  }
}
run().catch(console.dir);

app.listen(port, () => {
  console.log(`Asset Server listening on port ${port}`);
});

module.exports = app;