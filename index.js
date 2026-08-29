const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const { createRemoteJWKSet, jwtVerify } = require('jose');

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

app.use(cors({ origin: process.env.CLIENT_URI || 'http://localhost:3000' }));
app.use(express.json());

const uri = process.env.MONGODB_URI ;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

let db, doctorsCollection, appointsCollection;

const initialDoctors = [
  {
    name: "Dr. Sarah Jenkins",
    specialty: "Cardiology",
    title: "Senior Cardiologist & Heart Specialist",
    experienceYears: 14,
    rating: 4.9,
    reviewCount: 128,
    price: 150,
    currency: "USD",
    avatar: "https://images.unsplash.com/photo-1559839734-2b71ea197ec2?auto=format&fit=crop&q=80&w=400",
    location: "Heart & Vascular Center, Suite 402",
    bio: "Dr. Sarah Jenkins is a board-certified cardiologist with over 14 years of clinical experience in preventative cardiology, hypertension, and advanced heart health.",
    availableDays: ["Mon", "Wed", "Fri"]
  },
  {
    name: "Dr. Marcus Vance",
    specialty: "Dermatology",
    title: "Consultant Dermatologist",
    experienceYears: 10,
    rating: 4.8,
    reviewCount: 96,
    price: 120,
    currency: "USD",
    avatar: "https://images.unsplash.com/photo-1622253692010-333f2da6031d?auto=format&fit=crop&q=80&w=400",
    location: "SkinCare Clinic, 2nd Floor",
    bio: "Specialising in medical and cosmetic dermatology, Dr. Vance treats acne, eczema, psoriasis, and provides comprehensive skin wellness consultations.",
    availableDays: ["Tue", "Thu", "Sat"]
  },
  {
    name: "Dr. Elena Rostova",
    specialty: "Neurology",
    title: "Chief Neurologist & Brain Specialist",
    experienceYears: 16,
    rating: 5.0,
    reviewCount: 210,
    price: 180,
    currency: "USD",
    avatar: "https://images.unsplash.com/photo-1594824813566-88855ce78907?auto=format&fit=crop&q=80&w=400",
    location: "Neuroscience Institute, Block B",
    bio: "Dr. Rostova specializes in migraine treatment, stroke prevention, neurodegenerative conditions, and comprehensive neurological evaluations.",
    availableDays: ["Mon", "Tue", "Thu"]
  },
  {
    name: "Dr. James Wilson",
    specialty: "Pediatrics",
    title: "Senior Pediatrician",
    experienceYears: 12,
    rating: 4.9,
    reviewCount: 154,
    price: 100,
    currency: "USD",
    avatar: "https://images.unsplash.com/photo-1537368910025-700350fe46c7?auto=format&fit=crop&q=80&w=400",
    location: "Children's Health Pavilion, Room 105",
    bio: "Passionate about child development and wellness, Dr. Wilson provides warm, attentive pediatric care from newborn visits to adolescent health.",
    availableDays: ["Mon", "Wed", "Sat"]
  },
  {
    name: "Dr. Aisha Patel",
    specialty: "Orthopedics",
    title: "Orthopedic Surgeon & Joint Care Specialist",
    experienceYears: 11,
    rating: 4.8,
    reviewCount: 88,
    price: 160,
    currency: "USD",
    avatar: "https://images.unsplash.com/photo-1551836022-d5d88e9218df?auto=format&fit=crop&q=80&w=400",
    location: "Bone & Joint Clinic, Suite 301",
    bio: "Expert in sports injuries, knee and hip replacements, and non-surgical joint treatments.",
    availableDays: ["Wed", "Fri", "Sat"]
  },
  {
    name: "Dr. Robert Chen",
    specialty: "General Medicine",
    title: "Primary Care Physician",
    experienceYears: 9,
    rating: 4.7,
    reviewCount: 76,
    price: 90,
    currency: "USD",
    avatar: "https://images.unsplash.com/photo-1612349317150-e413f6a5b16d?auto=format&fit=crop&q=80&w=400",
    location: "Community Wellness Center",
    bio: "Dr. Chen focuses on holistic primary care, routine checkups, chronic disease management, and preventative health guidance.",
    availableDays: ["Mon", "Tue", "Wed", "Thu", "Fri"]
  }
];

let inMemoryAppoints = [];

let JWKS;
const getJWKS = () => {
  if (!JWKS) {
    const clientUri = process.env.CLIENT_URI || 'http://localhost:3000';
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
    const { payload } = await jwtVerify(token, jwks, { issuer: process.env.CLIENT_URI || 'http://localhost:3000', audience: process.env.CLIENT_URI || 'http://localhost:3000' });
    req.user = payload;
    console.log("Verified Better Auth Token Payload:", payload);
    next();
  } catch (error) {
    console.error("Token verification failed:", error.message);
    return res.status(401).json({ message: "Unauthorized" });
  }
};

async function connectDB() {
  try {
    await client.connect();
    db = client.db('docappoint_db');
    doctorsCollection = db.collection('doctors');
    appointsCollection = db.collection('appoints');

    const count = await doctorsCollection.countDocuments();
    if (count === 0) {
      await doctorsCollection.insertMany(initialDoctors);
      console.log("Seeded initial doctors database in MongoDB!");
    }
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

  // Fallback in-memory doctor search
  let result = initialDoctors;
  if (search) {
    const term = search.toLowerCase();
    result = result.filter(
      (d) => d.name.toLowerCase().includes(term) || d.specialty.toLowerCase().includes(term)
    );
  }
  if (specialty && specialty !== 'All Specialties') {
    const spec = specialty.toLowerCase();
    result = result.filter(
      (d) => d.specialty.toLowerCase() === spec
    );
  }
  res.send(result);
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

  const found = initialDoctors.find((d) => d._id === id || d._id.toString() === id);
  if (!found) {
    return res.status(404).json({ message: "Doctor not found" });
  }
  res.send(found);
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

app.listen(port, () => {
  console.log(`Backend server listening on port ${port}`);
});


