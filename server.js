require('dotenv').config(); // Load environment variables from .env

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path'); // For serving static files
const cors = require('cors')
const app = express();
const PORT = process.env.PORT || 8000;

// --- Middleware ---
app.use(express.json());
app.use(cors());   //For parsing JSON request bodies


// Serve static files from the 'MultipleFiles' directory
// Adjust this path if your frontend files are located elsewhere relative to the backend
// Serve login page at root
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname,'loginnew.html'));
});

// Explicitly serve other HTML files
app.get('/tablenew.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'tablenew.html'));
});

// --- MongoDB Connection ---
mongoose.connect(process.env.MONGO_URI)
.then(() => console.log('MongoDB connected successfully'))
.catch(err => console.error('MongoDB connection error:', err));

// --- Mongoose Schemas and Models ---

// User Model
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'user'], default: 'user' } // 'admin' for full access
});

// Hash password before saving
UserSchema.pre('save', async function(next) {
    if (this.isModified('password')) {
        this.password = await bcrypt.hash(this.password, 10);
    }
    next();
});

const User = mongoose.model('User', UserSchema);

// Purchase Model
const PurchaseSchema = new mongoose.Schema({
    buyerName: { type: String, required: true },
    products: { type: Array, required: true },
    platform: { type: String, required: true },
    email: { type: String, required: true },
    purchaseDate: { type: Date, required: true }, // Storing as string for simplicity, can be Date type
    grandTotal: { type: Number, required: true },
    gst: { type: String, enum: ['Yes', 'No'], required: true },
    billUpload: { type: Object, required: true }, // Bill file name/path (e.g., "bill_123.pdf")
    quantity: { type: Number, required: true },
    amount: { type: Number, required: true },
    mimetype: { type: String, enum: ['pdf', 'image', 'other'] }, // For bill preview
    billURL: {type: String, required: true}
});

const Purchase = mongoose.model('Purchase', PurchaseSchema);

// --- Authentication Middleware ---

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Expects "Bearer TOKEN"

    if (!token) {
        return res.status(401).json({ message: 'Authentication token required' }); // No token
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.error('JWT verification error:', err.message);
            return res.status(403).json({ message: 'Invalid or expired token' }); // Invalid token
        }
        req.user = user; // Attach user payload (id, username, role) to request
        next();
    });
};

const authorizeAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Access denied: Admins only' });
    }
    next();
};

// --- Routes ---

// Authentication Routes
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        // Basic validation
        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password are required' });
        }
        const newUser = new User({ username, password });
        await newUser.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        if (error.code === 11000) { // Duplicate key error (username already exists)
            return res.status(409).json({ message: 'Username already exists' });
        }
        res.status(500).json({ message: 'Error registering user', error: error.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ message: 'Invalid username or password' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid username or password' });
        }

        // Generate JWT token
        const token = jwt.sign(
            { id: user._id, username: user.username, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '1h' } // Token expires in 1 hour
        );

        res.json({ token, role: user.role });
    } catch (error) {
        res.status(500).json({ message: 'Server error during login', error: error.message });
    }
});

// Purchase Routes (Protected by authenticateToken and authorizeAdmin)
app.get('/api/purchases', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const purchases = await Purchase.find({});
        // Map _id to id for frontend compatibility
        const formattedPurchases = purchases.map(p => ({
            id: p._id, // MongoDB's _id
            buyerName: p.buyerName,
            productName: p.products,
            platform: p.platform,
            email: p.email,
            date: p.purchaseDate,
            grandTotal: p.grandTotal,
            gst: p.gst,
            billUpload: p.billUpload,
            quantity: p.quantity,
            amount: p.amount
        }));
        res.json(formattedPurchases);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching purchases', error: error.message });
    }
});

app.post('/api/purchases/delete', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const { ids } = req.body; // Array of IDs (strings) to delete
        if (!Array.isArray(ids) || ids.length === 0) {
            return res.status(400).json({ message: 'No IDs provided for deletion' });
        }
        // Convert string IDs to MongoDB ObjectIds
        const objectIds = ids.map(id => new mongoose.Types.ObjectId(id));
        const result = await Purchase.deleteMany({ _id: { $in: objectIds } });
        res.json({ message: `${result.deletedCount} records deleted successfully` });
    } catch (error) {
        res.status(500).json({ message: 'Error deleting purchases', error: error.message });
    }
});

// Route to get unique buyer names for dropdown (Protected)
app.get('/api/buyers', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const buyers = await Purchase.distinct('buyerName');
        res.json(buyers.sort()); // Return sorted unique buyer names
    } catch (error) {
        res.status(500).json({ message: 'Error fetching buyer names', error: error.message });
    }
});
const IMAGE_FOLDER = path.join(__dirname, 'uploads');

// Serve image in browser
app.get('/view/:billUpload', (req, res) => {
    console.log(req.params.billUpload);
    const imagePath = path.join(IMAGE_FOLDER, req.params.billUpload);
    console.log(imagePath);
    res.sendFile(imagePath);
});

// Download image
app.get('/download/:billUpload', (req, res) => {
    const imagePath = path.join(IMAGE_FOLDER, req.params.billUpload);
    res.download(imagePath, (err) => {
        if (err) {
            res.status(404).send('Image not found!');
        }
    });
});



// --- Initial Admin User Creation (for first time setup) ---
// This function will create an 'admin' user if one doesn't already exist.
// You can call it once when the server starts, then comment it out.
async function createInitialAdmin() {
    try {
        const adminExists = await User.findOne({ username: 'OM' });
        if (!adminExists) {
            const adminUser = new User({ username: 'OM', password: '123456', role: 'admin' });
            await adminUser.save();
            console.log('Initial admin user created: username "admin", password "adminpassword"');
            console.log('*** REMEMBER TO CHANGE THIS PASSWORD AFTER FIRST LOGIN! ***');
        }
    } catch (error) {
        console.error('Error creating initial admin user:', error);
    }
}

// Call the function to create an initial admin user when the server starts
// You might want to comment this out after the first successful run in production
createInitialAdmin();


// --- Start the server ---
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});