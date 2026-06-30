const express = require('express');
const cors = require('cors');
require('dotenv').config();
const { Pool } = require('pg');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(cors());
app.use(express.json());

// PostgreSQL Connection Pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// ============================================
// MIDDLEWARE
// ============================================

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// ============================================
// AUTH ENDPOINTS
// ============================================

app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = uuidv4();

    await pool.query(
      'INSERT INTO users (id, email, password, name) VALUES ($1, $2, $3, $4)',
      [userId, email, hashedPassword, name]
    );

    const token = jwt.sign({ userId, email }, process.env.JWT_SECRET);
    res.json({ token, userId });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (result.rows.length === 0) return res.status(400).json({ error: 'User not found' });

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) return res.status(400).json({ error: 'Invalid password' });

    const token = jwt.sign({ userId: user.id, email: user.email }, process.env.JWT_SECRET);
    res.json({ token, userId: user.id });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ============================================
// PROPERTIES ENDPOINTS
// ============================================

app.post('/api/properties', authenticateToken, async (req, res) => {
  try {
    const { address, unit } = req.body;
    const propertyId = uuidv4();

    await pool.query(
      'INSERT INTO properties (id, owner_id, address, unit) VALUES ($1, $2, $3, $4)',
      [propertyId, req.user.userId, address, unit]
    );

    res.json({ propertyId, address, unit });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/properties', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM properties WHERE owner_id = $1 ORDER BY created_at DESC',
      [req.user.userId]
    );
    res.json(result.rows);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ============================================
// TENANTS ENDPOINTS
// ============================================

app.post('/api/properties/:propertyId/tenants', authenticateToken, async (req, res) => {
  try {
    const { propertyId } = req.params;
    const { name, email, phone, monthlyRent } = req.body;
    const tenantId = uuidv4();

    await pool.query(
      'INSERT INTO tenants (id, property_id, name, email, phone, monthly_rent) VALUES ($1, $2, $3, $4, $5, $6)',
      [tenantId, propertyId, name, email, phone, monthlyRent]
    );

    res.json({ tenantId, name, email, phone, monthlyRent });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/properties/:propertyId/tenants', authenticateToken, async (req, res) => {
  try {
    const { propertyId } = req.params;
    const result = await pool.query(
      'SELECT * FROM tenants WHERE property_id = $1 ORDER BY created_at DESC',
      [propertyId]
    );
    res.json(result.rows);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ============================================
// RENT PAYMENTS ENDPOINTS
// ============================================

app.post('/api/rent-payments', authenticateToken, async (req, res) => {
  try {
    const { tenantId, amount, dueDate } = req.body;
    const paymentId = uuidv4();

    await pool.query(
      'INSERT INTO rent_payments (id, tenant_id, amount, due_date, status) VALUES ($1, $2, $3, $4, $5)',
      [paymentId, tenantId, amount, dueDate, 'pending']
    );

    res.json({ paymentId, amount, dueDate, status: 'pending' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/rent-payments/:tenantId', async (req, res) => {
  try {
    const { tenantId } = req.params;
    const result = await pool.query(
      'SELECT * FROM rent_payments WHERE tenant_id = $1 ORDER BY due_date DESC',
      [tenantId]
    );
    res.json(result.rows);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ============================================
// STRIPE PAYMENT INTENT
// ============================================

app.post('/api/payments/intent', async (req, res) => {
  try {
    const { amount, paymentId } = req.body;
    const amountInCents = Math.round(amount * 100);

    const paymentIntent = await stripe.paymentIntents.create({
      amount: amountInCents,
      currency: 'usd',
      metadata: { paymentId },
      payment_method_types: ['card', 'us_bank_account'],
    });

    res.json({ clientSecret: paymentIntent.client_secret });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ============================================
// STRIPE WEBHOOK (Settlement Notifications)
// ============================================

app.post('/api/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];

  try {
    const event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);

    if (event.type === 'payment_intent.succeeded') {
      const { id, metadata, amount_received } = event.data.object;
      const settlementDate = new Date(Date.now() + 1 * 24 * 60 * 60 * 1000); // Next business day

      await pool.query(
        'UPDATE rent_payments SET status = $1, stripe_payment_id = $2, settlement_date = $3 WHERE id = $4',
        ['completed', id, settlementDate, metadata.paymentId]
      );
    }

    res.json({ received: true });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ============================================
// DASHBOARD/SUMMARY
// ============================================

app.get('/api/dashboard/summary', authenticateToken, async (req, res) => {
  try {
    const rentDueResult = await pool.query(
      `SELECT SUM(amount) as total_due FROM rent_payments
       JOIN tenants ON rent_payments.tenant_id = tenants.id
       JOIN properties ON tenants.property_id = properties.id
       WHERE properties.owner_id = $1 AND rent_payments.status = 'pending'`,
      [req.user.userId]
    );

    const paymentsReceivedResult = await pool.query(
      `SELECT SUM(amount) as total_received FROM rent_payments
       JOIN tenants ON rent_payments.tenant_id = tenants.id
       JOIN properties ON tenants.property_id = properties.id
       WHERE properties.owner_id = $1 AND rent_payments.status = 'completed'
       AND rent_payments.settlement_date <= NOW()`,
      [req.user.userId]
    );

    const recentPaymentsResult = await pool.query(
      `SELECT rent_payments.*, tenants.name, tenants.email FROM rent_payments
       JOIN tenants ON rent_payments.tenant_id = tenants.id
       JOIN properties ON tenants.property_id = properties.id
       WHERE properties.owner_id = $1
       ORDER BY rent_payments.created_at DESC LIMIT 10`,
      [req.user.userId]
    );

    res.json({
      totalDue: rentDueResult.rows[0].total_due || 0,
      totalReceived: paymentsReceivedResult.rows[0].total_received || 0,
      recentPayments: recentPaymentsResult.rows,
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ============================================
// SERVER START
// ============================================

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 RentFast API running on port ${PORT}`);
});
