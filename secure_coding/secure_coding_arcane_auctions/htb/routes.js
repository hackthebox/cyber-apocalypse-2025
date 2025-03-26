
import express from 'express';
import prisma from './db.js';

const router = express.Router();

// --- Helper Middleware ---
const isAuthenticated = (req, res, next) => {
  if (req.session && req.session.user) {
    next();
  } else {
    return res.status(403).json({ error: 'Unauthorized' });
  }
};

// Render Home Page
router.get('/', async (req, res) => {
  res.render('index.html', { user: req.session.user });
});

// Render Item Detail Page
router.get('/item/:id', async (req, res) => {
  res.render('item.html', { user: req.session.user });
});

// Render Login Page
router.get('/login', (req, res) => {
  res.render('login.html', { user: req.session.user, error: null });
});

// Handle Login Submission (plain text passwords, AJAX response)
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required.' });
    }
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || user.password !== password) {
      return res.status(400).json({ error: 'Invalid email or password.' });
    }
    req.session.user = {
      id: user.id,
      email: user.email,
      username: user.username,
      gold_balance: user.gold_balance,
    };
    return res.json({ success: true });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Login failed.' });
  }
});

// Render Register Page
router.get('/register', (req, res) => {
  res.render('register.html', { user: req.session.user, error: null });
});

// Handle Registration Submission (plain text passwords, AJAX response)
router.post('/register', async (req, res) => {
  try {
    const { email, username, password } = req.body;
    if (!email || !username || !password) {
      return res.status(400).json({ error: 'Email, username, and password required.' });
    }
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists with that email.' });
    }
    const user = await prisma.user.create({ data: { email, username, password } });
    req.session.user = {
      id: user.id,
      email: user.email,
      username: user.username,
      gold_balance: user.gold_balance,
    };
    return res.json({ success: true });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Registration failed.' });
  }
});

// Logout (redirects to home)
router.get('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).send("Logout failed.");
    res.redirect('/');
  });
});

// --- Items & Bids API Endpoints ---
router.get('/api/items', async (req, res) => {
  try {
    const items = await prisma.item.findMany();
    res.json(items);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch items' });
  }
});

// Updated endpoint to include seller information.
router.get('/api/item/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const item = await prisma.item.findUnique({
      where: { id },
      include: { seller: { select: { username: true } } }
    });
    if (!item) return res.status(404).json({ error: 'Item not found' });
    res.json(item);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch item' });
  }
});

router.get('/api/items/:id/bids', async (req, res) => {
  try {
    const { id: itemId } = req.params;
    const bids = await prisma.bid.findMany({
      where: { itemId },
      orderBy: { amount: 'desc' },
      include: { user: { select: { username: true } } }
    });
    res.json(bids);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch bids' });
  }
});

router.get('/api/my-bids', isAuthenticated, async (req, res) => {
  try {
    const bids = await prisma.bid.findMany({
      where: { userId: req.session.user.id },
      orderBy: { createdAt: 'desc' },
      include: { item: { select: { name: true } } }
    });
    res.json(bids);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch user bids' });
  }
});

router.post('/api/bid', isAuthenticated, async (req, res) => {
  try {
    const { itemId, amount } = req.body;
    if (!itemId || !amount) {
      return res.status(400).json({ error: 'Invalid request data' });
    }
    const item = await prisma.item.findUnique({ where: { id: itemId } });
    if (!item) {
      return res.status(404).json({ error: 'Item not found' });
    }
    if (amount <= item.currentBid) {
      return res.status(400).json({ error: 'Bid must be higher than the current bid' });
    }
    const user = await prisma.user.findUnique({ where: { id: req.session.user.id } });
    if (user.gold_balance < amount) {
      return res.status(400).json({ error: 'Insufficient gold' });
    }
    await prisma.bid.create({
      data: {
        amount,
        item: { connect: { id: itemId } },
        user: { connect: { id: user.id } }
      }
    });
    await prisma.user.update({
      where: { id: user.id },
      data: { gold_balance: user.gold_balance - amount }
    });
    await prisma.item.update({
      where: { id: itemId },
      data: { currentBid: amount }
    });
    res.json({ success: true, newBid: amount });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to place bid' });
  }
});

// Filtering Endpoint: Accepts a Prisma-style filter object from the client in req.body.filter.

router.post('/api/filter', async (req, res) => {
  try {
    let filter = req.body.filter || {};

    // Reject any filter that includes select or include properties.
    if (filter.select || filter.include) {
      return res.status(400).json({ error: 'Invalid filter: select/include are not allowed' });
    }

    // Alternatively, you could whitelist only allowed keys:
    // const allowedKeys = ['where', 'orderBy', 'skip', 'take', 'cursor'];
    // filter = allowedKeys.reduce((acc, key) => {
    //   if (filter[key] !== undefined) {
    //     acc[key] = filter[key];
    //   }
    //   return acc;
    // }, {});

    const items = await prisma.item.findMany(filter);
    res.json(items);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Filtering error' });
  }
});


export default router;
