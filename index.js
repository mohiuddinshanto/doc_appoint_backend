const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const { createRemoteJWKSet, jwtVerify } = require('jose');

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

const allowedOrigins = process.env.CLIENT_URI
  ? process.env.CLIENT_URI.split(',').map((origin) => origin.trim()).filter(Boolean)
  : [];

app.use(cors({
  origin(origin, callback) {
    // Requests from tools such as curl do not include an Origin header.
    if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('Origin is not allowed by CORS'));
  }
}));
app.use(express.json());

const uri = process.env.MONGODB_URI;

const client = uri
  ? new MongoClient(uri, {
      serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
      }
    })
  : null;

let db, doctorsCollection, appointsCollection;


let inMemoryAppoints = [];

let JWKS;
const getJWKS = () => {
  if (!JWKS) {
    const clientUri = process.env.CLIENT_URI;
    const jwksUrl = new URL(`${clientUri}/api/auth/jwks`);
    JWKS = createRemoteJWKSet(jwksUrl);
  }
  return JWKS;
};

const verifyToken = async (req, res, next) => {
  const header = req?.headers.authorization;
  if (!header) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  const token = header.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  try {
    const jwks = getJWKS();
    const { payload } = await jwtVerify(token, jwks, { issuer: process.env.CLIENT_URI, audience: process.env.CLIENT_URI });
    req.user = payload;
    console.log("Verified Better Auth Token Payload:", payload);
    next();
  } catch (error) {
    console.error("Token verification failed:", error.message);
    return res.status(401).json({ message: "Unauthorized" });
  }
};

async function connectDB() {
  if (!client) {
    console.warn('MONGODB_URI is not configured. Database routes will be unavailable.');
    return;
  }

  try {
    await client.connect();
    db = client.db('docappoint_db');
    doctorsCollection = db.collection('doctors');
    appointsCollection = db.collection('appoints');
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } catch (err) {
    console.warn("MongoDB connection warning (running with in-memory store):", err.message);
  }
}

connectDB();

// ================================= Root API ============================================
app.get('/', (req, res) => {
  res.send('Hello World!');
});

// ================================= Doctors API ============================================
app.get('/doctors', async (req, res) => {
  const { search, specialty } = req.query;
  let query = {};

  const conditions = [];
  if (search) {
    conditions.push({
      $or: [
        { name: { $regex: search, $options: 'i' } },
        { specialty: { $regex: search, $options: 'i' } }
      ]
    });
  }

  if (specialty && specialty !== 'All Specialties') {
    conditions.push({
      specialty: { $regex: `^${specialty}$`, $options: 'i' }
    });
  }

  if (conditions.length > 0) {
    query = conditions.length === 1 ? conditions[0] : { $and: conditions };
  }

  if (doctorsCollection) {
    try {
      const doctors = await doctorsCollection.find(query).toArray();
      return res.send(doctors);
    } catch (e) {
      // fallback
    }
  }

  res.status(503).json({ message: 'Doctors are temporarily unavailable. Please try again shortly.' });
});

app.get('/doctors/:id', verifyToken, async (req, res) => {
  const id = req.params.id;
  if (doctorsCollection) {
    try {
      const doctor = await doctorsCollection.findOne({ _id: new ObjectId(id) });
      if (doctor) return res.send(doctor);
    } catch (e) {
      // fallback
    }
  }

  res.status(503).json({ message: 'Doctors are temporarily unavailable. Please try again shortly.' });
});

// ================================= Appoints API ============================================
app.get('/appoints/:userId', verifyToken, async (req, res) => {
  const { userId } = req.params;
  if (userId !== req.user.sub) return res.status(403).json({ message: "Forbidden" });
  if (appointsCollection) {
    try {
      const query = { userId: userId };
      const result = await appointsCollection.find(query).toArray();
      return res.json(result);
    } catch (e) {}
  }

  const userAppts = inMemoryAppoints.filter((a) => a.userId === userId);
  res.json(userAppts);
});

app.get('/appoints', verifyToken, async (req, res) => {
  if (appointsCollection) {
    try {
      const result = await appointsCollection.find().toArray();
      return res.json(result);
    } catch (e) {}
  }

  res.json(inMemoryAppoints);
});

app.post('/appoints', verifyToken, async (req, res) => {
  const appointsData = req.body;
  const userId = req.user.sub;
  const newAppt = {
    ...appointsData,
    userId,
    createdAt: new Date().toISOString()
  };

  if (appointsCollection) {
    try {
      const result = await appointsCollection.insertOne(newAppt);
      return res.json({ _id: result.insertedId.toString(), acknowledged: result.acknowledged });
    } catch (e) {
      return res.status(500).json({ message: "Unable to create the appointment." });
    }
  }

  res.status(503).json({ message: "MongoDB is unavailable." });
});

app.patch('/appoints/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  const updatedData = req.body;
  console.log("Update appointment:", id, updatedData);

  if (appointsCollection) {
    try {
      const result = await appointsCollection.updateOne(
        { _id: new ObjectId(id), userId: req.user.sub },
        { $set: updatedData }
      );
      return res.json(result);
    } catch (e) {}
  }

  const index = inMemoryAppoints.findIndex((a) => (a._id === id || a.id === id) && a.userId === req.user.sub);
  if (index !== -1) {
    inMemoryAppoints[index] = { ...inMemoryAppoints[index], ...updatedData };
  }
  res.json({ modifiedCount: 1 });
});

app.delete('/appoints/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  if (appointsCollection) {
    try {
      const result = await appointsCollection.deleteOne({ _id: new ObjectId(id), userId: req.user.sub });
      return res.json(result);
    } catch (e) {}
  }

  inMemoryAppoints = inMemoryAppoints.filter((a) => (a._id !== id && a.id !== id) || a.userId !== req.user.sub);
  res.json({ deletedCount: 1 });
});

if (process.env.NODE_ENV !== 'production') {
  app.listen(port, () => {
    console.log(`Backend server listening on port ${port}`);
  });
}

module.exports = app;
