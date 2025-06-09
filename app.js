require('dotenv').config(); 

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const path = require('path'); 
const app = express();
const PORT = 3000;



const JWT_SECRET = process.env.JWT_SECRET;
const DB_URI = process.env.DB_URI;

mongoose.connect(DB_URI)
  .then(() => console.log('MongoDB Atlas se successfully connect ho gaye!'))
  .catch(err => console.error('MongoDB Atlas connection error:', err));


const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  price: { type: Number, required: true, min: 0 },
  category: String,
  description: String,
  createdAt: { type: Date, default: Date.now }
});
const Product = mongoose.model('Product', productSchema);


const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    minlength: 3
  },
  email: {
    type: String,
    required: true,
    unique: true,
    match: /.+\@.+\..+/
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  }
});
const User = mongoose.model('User', userSchema);


app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());


app.use(express.static('public'));

app.post('/api/signup', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const existingUser = await User.findOne({ $or: [{ username }, { email }] });
        if (existingUser) {
            return res.status(400).json({ message: 'Username ya Email pehle se maujood hai.' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, email, password: hashedPassword });
        await newUser.save();
        res.status(201).json({ message: 'User successfully register ho gaya!', userId: newUser._id });
    } catch (err) {
        console.error('Registration error:', err);
        if (err.name === 'ValidationError') {
            return res.status(400).json({ message: err.message });
        }
        res.status(500).json({ message: 'Registration karte waqt server error hui', error: err.message });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ message: 'Invalid username ya password.' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid username ya password.' });
        }
        const token = jwt.sign(
            { userId: user._id, username: user.username },
            JWT_SECRET,
            { expiresIn: '1h' }
        );
        res.json({ message: 'Login successful!', token });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ message: 'Login karte waqt server error hui', error: err.message });
    }
});


const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; 
    if (token == null) {
        return res.status(401).json({ message: 'Authentication token missing.' });
    }
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error('JWT verification failed:', err.message);
            return res.status(403).json({ message: 'Invalid ya expired token.' });
        }
        req.user = user;
        next();
    });
};


app.get('/api/protected', authenticateToken, (req, res) => {
    res.json({
        message: 'Ye ek protected resource hai!',
        user: req.user, 
        accessTime: new Date().toLocaleString()
    });
});


app.post('/api/products', authenticateToken, async (req, res) => { 
    try {
        const { name, price, category, description } = req.body;
        const newProduct = new Product({ name, price, category, description });
        await newProduct.save();
        res.status(201).json({ message: 'Product successfully created!', product: newProduct });
    } catch (err) {
        console.error('Product creation error:', err);
        if (err.name === 'ValidationError') {
            return res.status(400).json({ message: err.message });
        }
        res.status(500).json({ message: 'Product banate waqt server error hui', error: err.message });
    }
});


app.get('/api/products', async (req, res) => {
    try {
        const products = await Product.find({});
        res.json(products);
    } catch (err) {
        console.error('Fetching products error:', err);
        res.status(500).json({ message: 'Products fetch karte waqt server error hui', error: err.message });
    }
});


app.get('/api/products/:id', async (req, res) => {
    try {
        const productId = req.params.id;

        if (!mongoose.Types.ObjectId.isValid(productId)) {
            return res.status(400).json({ message: 'Invalid Product ID format.' });
        }
        const product = await Product.findById(productId);
        if (!product) {
            return res.status(404).json({ message: 'Product nahi mila.' });
        }
        res.json(product);
    } catch (err) {
        console.error('Fetching product by ID error:', err);
        res.status(500).json({ message: 'Product fetch karte waqt server error hui', error: err.message });
    }
});


app.patch('/api/products/:id', authenticateToken, async (req, res) => { 
    try {
        const productId = req.params.id;
        if (!mongoose.Types.ObjectId.isValid(productId)) {
            return res.status(400).json({ message: 'Invalid Product ID format.' });
        }
        const updatedProduct = await Product.findByIdAndUpdate(
            productId,
            req.body,
            { new: true, runValidators: true }
        );
        if (!updatedProduct) {
            return res.status(404).json({ message: 'Product nahi mila.' });
        }
        res.json({ message: 'Product successfully updated!', product: updatedProduct });
    } catch (err) {
        console.error('Product update error:', err);
        if (err.name === 'ValidationError') {
            return res.status(400).json({ message: err.message });
        }
        res.status(500).json({ message: 'Product update karte waqt server error hui', error: err.message });
    }
});


app.delete('/api/products/:id', authenticateToken, async (req, res) => { 
    try {
        const productId = req.params.id;
        if (!mongoose.Types.ObjectId.isValid(productId)) {
            return res.status(400).json({ message: 'Invalid Product ID format.' });
        }
        const deletedProduct = await Product.findByIdAndDelete(productId);
        if (!deletedProduct) {
            return res.status(404).json({ message: 'Product nahi mila.' });
        }
        res.json({ message: 'Product successfully deleted!', product: deletedProduct });
    } catch (err) {
        console.error('Product deletion error:', err);
        res.status(500).json({ message: 'Product delete karte waqt server error hui', error: err.message });
    }
});



app.use((req, res) => {
    res.status(404).send('<h1>404 Page Not Found</h1><p>Maaf kijiye, ye page nahi mila!</p>');
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
  console.log('--- Authentication Endpoints ---');
  console.log(`POST   http://localhost:${PORT}/api/register (User Signup)`);
  console.log(`POST   http://localhost:${PORT}/api/login (User Login)`);
  console.log(`GET    http://localhost:${PORT}/api/protected (Requires JWT Token)`);
  console.log('--- Product CRUD Endpoints (now partially protected) ---');
  console.log(`POST   http://localhost:${PORT}/api/products (PROTECTED)`);
  console.log(`GET    http://localhost:${PORT}/api/products (OPEN)`);
  console.log(`GET    http://localhost:${PORT}/api/products/:id (OPEN)`);
  console.log(`PATCH  http://localhost:${PORT}/api/products/:id (PROTECTED)`);
  console.log(`DELETE http://localhost:${PORT}/api/products/:id (PROTECTED)`);
});