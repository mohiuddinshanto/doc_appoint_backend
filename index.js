const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const { createRemoteJWKSet, jwtVerify } = require('jose');

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

const normalizeOrigins = (rawValue = '') =>
  rawValue
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean)
    .filter((origin, index, arr) => arr.indexOf(origin) === index);

const allowedOrigins = normalizeOrigins(
  [
    process.env.CLIENT_URI,
    process.env.FRONTEND_URL,
    process.env.NEXT_PUBLIC_APP_URL,
    process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : '',
    'http://localhost:3000',
    'http://localhost:3001',
  ].join(',')
);

app.use(cors({
  origin(origin, callback) {
    if (!origin) {
      return callback(null, true);
    }

    if (allowedOrigins.includes(origin) || /https:\/\/.*\.vercel\.app$/i.test(origin)) {
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
let connectionPromise;
let appointmentIndexReady = false;


let inMemoryAppoints = [];

let JWKS;
const getClientUri = () => {
  if (process.env.CLIENT_URI) return process.env.CLIENT_URI;
  if (allowedOrigins.length > 0) return allowedOrigins[0];
  return 'http://localhost:3000';
};

const getJWKS = () => {
  if (!JWKS) {
    const clientUri = getClientUri();
    const jwksUrl = new URL(`${clientUri.replace(/\/$/, '')}/api/auth/jwks`);
    JWKS = createRemoteJWKSet(jwksUrl);
  }
  return JWKS;
};

// Keep the first booking for each slot and cancel old duplicate records.
async function resolveDuplicateUpcomingAppointments() {
  const appointments = await appointsCollection
    .find({ status: 'upcoming', compositeSlotKey: { $type: 'string' } })
    .sort({ createdAt: 1, bookedAt: 1, _id: 1 })
    .toArray();

  const usedSlots = new Set();
  const duplicateIds = [];

  for (const appointment of appointments) {
    if (usedSlots.has(appointment.compositeSlotKey)) {
      duplicateIds.push(appointment._id);
    } else {
      usedSlots.add(appointment.compositeSlotKey);
    }
  }

  if (duplicateIds.length === 0) return;

  await appointsCollection.updateMany(
    { _id: { $in: duplicateIds }, status: 'upcoming' },
    {
      $set: {
        status: 'cancelled',
        cancelledAt: new Date().toISOString(),
        cancellationReason: 'Duplicate booking for the same slot.',
      },
    }
  );

  console.warn(`Cancelled ${duplicateIds.length} old duplicate appointment(s).`);
}

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
    const validIssuers = [...new Set([process.env.CLIENT_URI, ...allowedOrigins].filter(Boolean))];
    const { payload } = await jwtVerify(token, jwks, {
      issuer: validIssuers,
      audience: validIssuers,
    });
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

  if (!connectionPromise) {
    connectionPromise = client
      .connect()
      .then(async () => {
        db = client.db('docappoint_db');
        doctorsCollection = db.collection('doctors');
        appointsCollection = db.collection('appoints');
        console.log("Pinged your deployment. You successfully connected to MongoDB!");

        // Only active appointments reserve a slot. This is the authoritative
        // race-condition guard: two concurrent inserts for the same slot
        // cannot both succeed.
        try {
          await resolveDuplicateUpcomingAppointments();
          await appointsCollection.createIndex(
            { compositeSlotKey: 1 },
            {
              name: 'unique_upcoming_composite_slot',
              unique: true,
              partialFilterExpression: { status: 'upcoming' },
            }
          );
          appointmentIndexReady = true;
        } catch (error) {
          // Do not accept bookings without the race-condition guard. Most
          // commonly this means existing duplicate upcoming records must be
          // resolved before the partial unique index can be created.
          appointmentIndexReady = false;
          console.error('Appointment unique index is unavailable:', error.message);
        }
      })
      .catch((err) => {
        // Allow a later serverless invocation to retry after a transient failure.
        connectionPromise = undefined;
        console.warn("MongoDB connection warning (running with in-memory store):", err.message);
      });
  }

  // Vercel may receive a request while a cold instance is still connecting.
  // Every database route must wait for that shared connection attempt.
  await connectionPromise;
}

connectDB();

// ================================= Root API ============================================
app.get('/', (req, res) => {
  res.send('Hello World!');
});

// ================================= Doctors API ============================================
app.get('/doctors', async (req, res) => {
  await connectDB();
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
  await connectDB();
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
// This endpoint intentionally exposes availability only, never appointment or
// patient details. It is safe for the slot-picker to call for every user.
// Keep it before `/appoints/:userId`, otherwise Express would treat
// "availability" as a user ID.
app.get('/appoints/availability', async (req, res) => {
  await connectDB();
  const { serviceId, date } = req.query;

  if (typeof serviceId !== 'string' || typeof date !== 'string' || !serviceId || !date) {
    return res.status(400).json({ message: 'serviceId and date are required.' });
  }

  if (appointsCollection) {
    try {
      const appointments = await appointsCollection
        .find(
          { serviceId, date, status: 'upcoming' },
          { projection: { compositeSlotKey: 1 } }
        )
        .toArray();
      return res.json({
        bookedSlotKeys: appointments
          .map((appointment) => appointment.compositeSlotKey)
          .filter((key) => typeof key === 'string'),
      });
    } catch (e) {
      return res.status(500).json({ message: 'Unable to load slot availability.' });
    }
  }

  res.status(503).json({ message: 'MongoDB is unavailable.' });
});

app.get('/appoints/:userId', verifyToken, async (req, res) => {
  await connectDB();
  const { userId } = req.params;
  if (userId !== req.user.sub) return res.status(403).json({ message: "Forbidden" });
  if (appointsCollection) {
    try {
      const query = { userId: userId };
      const result = await appointsCollection.find(query).toArray();
      return res.json(result);
    } catch (e) { }
  }

  const userAppts = inMemoryAppoints.filter((a) => a.userId === userId);
  res.json(userAppts);
});

app.get('/appoints', verifyToken, async (req, res) => {
  await connectDB();
  // Never return every patient's bookings to an authenticated user. The
  // identity comes from the verified JWT, not from a client-provided value.
  const userId = req.user.sub;
  if (appointsCollection) {
    try {
      const result = await appointsCollection.find({ userId }).toArray();
      return res.json(result);
    } catch (e) { }
  }

  res.json(inMemoryAppoints.filter((appointment) => appointment.userId === userId));
});

app.post('/appoints', verifyToken, async (req, res) => {
  await connectDB();
  const appointsData = req.body;
  const userId = req.user.sub;
  const { compositeSlotKey, serviceId, date, slotId } = appointsData;

  if (
    typeof compositeSlotKey !== 'string' ||
    typeof serviceId !== 'string' ||
    typeof date !== 'string' ||
    typeof slotId !== 'string' ||
    compositeSlotKey !== `${serviceId}::${date}::${slotId}`
  ) {
    return res.status(400).json({ message: 'Invalid appointment slot.' });
  }

  const newAppt = {
    ...appointsData,
    userId,
    // The client must not be able to create a non-reserving appointment.
    status: 'upcoming',
    createdAt: new Date().toISOString()
  };

  if (appointsCollection) {
    if (!appointmentIndexReady) {
      return res.status(503).json({
        message: 'Booking is temporarily unavailable while appointment data is being secured.',
      });
    }

    try {
      // Gives a clear response in the normal case. The unique index below is
      // still required because this check and insert are not atomic together.
      const existing = await appointsCollection.findOne({
        compositeSlotKey,
        status: 'upcoming',
      });
      if (existing) {
        return res.status(409).json({ message: 'This slot is already booked.' });
      }

      const result = await appointsCollection.insertOne(newAppt);
      return res.json({ _id: result.insertedId.toString(), acknowledged: result.acknowledged });
    } catch (e) {
      if (e && e.code === 11000) {
        return res.status(409).json({ message: 'This slot is already booked.' });
      }
      return res.status(500).json({ message: "Unable to create the appointment." });
    }
  }

  res.status(503).json({ message: "MongoDB is unavailable." });
});

app.patch('/appoints/:id', verifyToken, async (req, res) => {
  await connectDB();
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
    } catch (e) { }
  }

  const index = inMemoryAppoints.findIndex((a) => (a._id === id || a.id === id) && a.userId === req.user.sub);
  if (index !== -1) {
    inMemoryAppoints[index] = { ...inMemoryAppoints[index], ...updatedData };
  }
  res.json({ modifiedCount: 1 });
});

app.delete('/appoints/:id', verifyToken, async (req, res) => {
  await connectDB();
  const { id } = req.params;
  if (appointsCollection) {
    try {
      const result = await appointsCollection.deleteOne({ _id: new ObjectId(id), userId: req.user.sub });
      return res.json(result);
    } catch (e) { }
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
