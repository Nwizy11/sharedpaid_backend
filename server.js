const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
.then(() => console.log('✅ MongoDB Connected'))
.catch(err => console.error('❌ MongoDB Connection Error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  balance: { type: Number, default: 0 },
  totalDeposited: { type: Number, default: 0 },
  totalWithdrawn: { type: Number, default: 0 },
  status: { type: String, default: 'active', enum: ['active', 'suspended', 'pending'] },
  isAdmin: { type: Boolean, default: false },
  walletAddress: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Investment Schema
const investmentSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  plan: { type: String, required: true, enum: ['gold', 'silver', 'platinum'] },
  amount: { type: Number, required: true },
  initialAmount: { type: Number, required: true },
  roi: { type: Number, required: true },
  dailyReturn: { type: Number, required: true },
  daysElapsed: { type: Number, default: 0 },
  status: { type: String, default: 'active', enum: ['active', 'completed', 'cancelled'] },
  startDate: { type: Date, default: Date.now },
  maturityDate: { type: Date },
  lastUpdated: { type: Date, default: Date.now }
});

const Investment = mongoose.model('Investment', investmentSchema);

// Transaction Schema
const transactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, required: true, enum: ['deposit', 'withdrawal', 'profit', 'bonus'] },
  amount: { type: Number, required: true },
  status: { type: String, default: 'pending', enum: ['pending', 'completed', 'failed', 'cancelled', 'waiting', 'confirming', 'confirmed', 'sending', 'partially_paid', 'finished', 'expired'] },
  paymentId: { type: String },
  invoiceId: { type: String },
  invoiceUrl: { type: String },
  payAddress: { type: String },
  payCurrency: { type: String, default: 'btc' },
  payAmount: { type: String },
  priceAmount: { type: Number },
  priceCurrency: { type: String, default: 'usd' },
  walletAddress: { type: String },
  txHash: { type: String },
  description: { type: String },
  plan: { type: String },
  createdAt: { type: Date, default: Date.now },
  completedAt: { type: Date }
});

const Transaction = mongoose.model('Transaction', transactionSchema);

// NowPayments API Configuration
const NOWPAYMENTS_API_KEY = process.env.NOWPAYMENTS_API_KEY;
const NOWPAYMENTS_API_URL = 'https://api.nowpayments.io/v1';

// NowPayments API Request Helper
const nowpaymentsRequest = async (endpoint, method = 'GET', data = null) => {
  try {
    const config = {
      method,
      url: `${NOWPAYMENTS_API_URL}${endpoint}`,
      headers: {
        'x-api-key': NOWPAYMENTS_API_KEY,
        'Content-Type': 'application/json'
      }
    };

    if (data) {
      config.data = data;
    }

    const response = await axios(config);
    return response.data;
  } catch (error) {
    console.error('NowPayments API Error:', error.response?.data || error.message);
    throw error;
  }
};

// Auth Middleware
const authMiddleware = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ error: 'No authentication token' });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }
    
    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid authentication token' });
  }
};

// Admin Middleware
const adminMiddleware = (req, res, next) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// ==================== AUTH ROUTES ====================

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const user = new User({
      name,
      email,
      password: hashedPassword
    });
    
    await user.save();
    
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    
    res.status(201).json({
      message: 'Registration successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        balance: user.balance,
        isAdmin: user.isAdmin
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    
    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        balance: user.balance,
        isAdmin: user.isAdmin,
        walletAddress: user.walletAddress
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get current user
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  res.json({
    user: {
      id: req.user._id,
      name: req.user.name,
      email: req.user.email,
      balance: req.user.balance,
      totalDeposited: req.user.totalDeposited,
      totalWithdrawn: req.user.totalWithdrawn,
      isAdmin: req.user.isAdmin,
      walletAddress: req.user.walletAddress,
      status: req.user.status
    }
  });
});

// ==================== INVESTMENT ROUTES ====================

// Create investment (deposit)
app.post('/api/investments/create', authMiddleware, async (req, res) => {
  try {
    const { plan, amount, payCurrency = 'btc' } = req.body;
    
    const plans = {
      gold: { min: 50, roi: 30 },
      silver: { min: 100, roi: 50 },
      platinum: { min: 200, roi: 90 }
    };
    
    if (!plans[plan]) {
      return res.status(400).json({ error: 'Invalid plan' });
    }
    
    if (amount < plans[plan].min) {
      return res.status(400).json({ error: `Minimum investment for ${plan} is $${plans[plan].min}` });
    }
    
    // Create NowPayments invoice
    const orderId = `INV-${Date.now()}-${req.user._id}`;
    
    const paymentData = {
      price_amount: amount,
      price_currency: 'usd',
      pay_currency: payCurrency,
      ipn_callback_url: `${process.env.BACKEND_URL}/api/webhooks/nowpayments`,
      order_id: orderId,
      order_description: `${plan.charAt(0).toUpperCase() + plan.slice(1)} Plan Investment - $${amount}`,
      success_url: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/dashboard?payment=success`,
      cancel_url: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/dashboard?payment=cancelled`
    };
    
    console.log('Creating NowPayments invoice:', paymentData);
    
    // Use the invoice endpoint instead of payment
    const invoice = await nowpaymentsRequest('/invoice', 'POST', paymentData);
    
    console.log('NowPayments invoice response:', invoice);
    
    if (invoice && invoice.id) {
      // Construct proper invoice URL
      const invoiceUrl = `https://nowpayments.io/payment/?iid=${invoice.id}`;
      
      // Create transaction with invoice data
      const transaction = new Transaction({
        userId: req.user._id,
        type: 'deposit',
        amount,
        status: 'waiting',
        paymentId: invoice.payment_id || invoice.id,
        invoiceId: invoice.id,
        invoiceUrl: invoiceUrl,
        payAddress: invoice.pay_address,
        payCurrency: invoice.pay_currency || payCurrency,
        payAmount: invoice.pay_amount,
        priceAmount: invoice.price_amount || amount,
        priceCurrency: invoice.price_currency || 'usd',
        description: `${plan.charAt(0).toUpperCase() + plan.slice(1)} Plan Investment`,
        plan: plan
      });
      
      await transaction.save();
      
      console.log('Transaction created:', transaction._id);
      console.log('Invoice URL:', invoiceUrl);
      
      res.json({
        message: 'Invoice created successfully',
        invoiceUrl: invoiceUrl,
        invoiceId: invoice.id,
        paymentId: invoice.payment_id || invoice.id,
        payAddress: invoice.pay_address,
        payAmount: invoice.pay_amount,
        payCurrency: invoice.pay_currency || payCurrency,
        transactionId: transaction._id
      });
    } else {
      throw new Error('Invoice creation failed: ' + JSON.stringify(invoice));
    }
  } catch (error) {
    console.error('Investment creation error:', error.response?.data || error.message);
    res.status(500).json({ 
      error: 'Failed to create investment',
      details: error.response?.data?.message || error.message 
    });
  }
});

// Get user investments
app.get('/api/investments', authMiddleware, async (req, res) => {
  try {
    const investments = await Investment.find({ userId: req.user._id }).sort({ createdAt: -1 });
    res.json({ investments });
  } catch (error) {
    console.error('Get investments error:', error);
    res.status(500).json({ error: 'Failed to fetch investments' });
  }
});

// Get single investment
app.get('/api/investments/:id', authMiddleware, async (req, res) => {
  try {
    const investment = await Investment.findOne({ _id: req.params.id, userId: req.user._id });
    
    if (!investment) {
      return res.status(404).json({ error: 'Investment not found' });
    }
    
    res.json({ investment });
  } catch (error) {
    console.error('Get investment error:', error);
    res.status(500).json({ error: 'Failed to fetch investment' });
  }
});

// ==================== TRANSACTION ROUTES ====================

// Get user transactions
app.get('/api/transactions', authMiddleware, async (req, res) => {
  try {
    const transactions = await Transaction.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .limit(50);
    
    res.json({ transactions });
  } catch (error) {
    console.error('Get transactions error:', error);
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

// Get payment status
app.get('/api/transactions/status/:paymentId', authMiddleware, async (req, res) => {
  try {
    const { paymentId } = req.params;
    const status = await nowpaymentsRequest(`/payment/${paymentId}`);
    res.json({ status });
  } catch (error) {
    console.error('Get payment status error:', error);
    res.status(500).json({ error: 'Failed to fetch payment status' });
  }
});

// Manual payment status check and update
app.post('/api/transactions/check-status/:transactionId', authMiddleware, async (req, res) => {
  try {
    const transaction = await Transaction.findOne({ 
      _id: req.params.transactionId,
      userId: req.user._id 
    });
    
    if (!transaction) {
      return res.status(404).json({ error: 'Transaction not found' });
    }
    
    if (transaction.type !== 'deposit') {
      return res.status(400).json({ error: 'Not a deposit transaction' });
    }
    
    if (transaction.status === 'completed') {
      return res.json({ 
        updated: false, 
        message: 'Payment already completed' 
      });
    }
    
    // Check payment status from NowPayments
    let paymentStatus;
    try {
      paymentStatus = await nowpaymentsRequest(`/payment/${transaction.paymentId}`);
    } catch (error) {
      return res.status(500).json({ error: 'Failed to fetch payment status from gateway' });
    }
    
    console.log('Payment status check:', paymentStatus);
    
    const oldStatus = transaction.status;
    transaction.status = paymentStatus.payment_status;
    
    // Handle successful payment
    if (paymentStatus.payment_status === 'finished') {
      transaction.status = 'completed';
      transaction.completedAt = new Date();
      
      if (paymentStatus.outcome_amount) {
        transaction.payAmount = paymentStatus.outcome_amount;
      }
      
      await transaction.save();
      
      // Get user
      const user = await User.findById(transaction.userId);
      
      if (user && oldStatus !== 'completed') {
        // Add to balance (only if not already completed)
        user.balance += transaction.amount;
        user.totalDeposited += transaction.amount;
        await user.save();
        
        console.log(`Added ${transaction.amount} to user ${user.email} balance`);
        
        // Create investment
        const plans = {
          gold: { roi: 30 },
          silver: { roi: 50 },
          platinum: { roi: 90 }
        };
        
        const plan = transaction.plan || 'gold';
        const roi = plans[plan].roi;
        const dailyReturn = (transaction.amount * (roi / 100)) / 30;
        const maturityDate = new Date();
        maturityDate.setDate(maturityDate.getDate() + 30);
        
        const investment = new Investment({
          userId: user._id,
          plan,
          amount: transaction.amount,
          initialAmount: transaction.amount,
          roi,
          dailyReturn,
          maturityDate
        });
        
        await investment.save();
        
        console.log('Investment created successfully');
        
        return res.json({
          updated: true,
          message: 'Payment confirmed! Your account has been credited and investment activated.',
          transaction,
          investment
        });
      }
    } else if (paymentStatus.payment_status === 'failed' || paymentStatus.payment_status === 'expired') {
      transaction.status = 'failed';
      await transaction.save();
      return res.json({
        updated: true,
        message: `Payment ${paymentStatus.payment_status}. Please try again.`
      });
    } else {
      // Still pending/waiting/confirming
      await transaction.save();
      return res.json({
        updated: false,
        message: `Payment status: ${paymentStatus.payment_status}. Please wait for confirmation.`
      });
    }
    
    res.json({ updated: false, message: 'No changes detected' });
  } catch (error) {
    console.error('Check payment status error:', error);
    res.status(500).json({ error: 'Failed to check payment status' });
  }
});

// Request withdrawal
app.post('/api/transactions/withdraw', authMiddleware, async (req, res) => {
  try {
    const { amount, walletAddress } = req.body;
    
    if (!walletAddress) {
      return res.status(400).json({ error: 'Wallet address is required' });
    }
    
    if (amount < 10) {
      return res.status(400).json({ error: 'Minimum withdrawal amount is $10' });
    }
    
    if (amount > req.user.balance) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    const transaction = new Transaction({
      userId: req.user._id,
      type: 'withdrawal',
      amount,
      status: 'pending',
      walletAddress,
      description: 'Withdrawal request'
    });
    
    await transaction.save();
    
    req.user.balance -= amount;
    await req.user.save();
    
    res.json({
      message: 'Withdrawal request submitted successfully',
      transaction: {
        id: transaction._id,
        amount: transaction.amount,
        status: transaction.status,
        createdAt: transaction.createdAt
      }
    });
  } catch (error) {
    console.error('Withdrawal error:', error);
    res.status(500).json({ error: 'Failed to process withdrawal' });
  }
});

// ==================== WEBHOOK ROUTES ====================

// NowPayments IPN webhook
app.post('/api/webhooks/nowpayments', async (req, res) => {
  try {
    const paymentData = req.body;
    const receivedSignature = req.headers['x-nowpayments-sig'];
    
    console.log('NowPayments IPN received:', JSON.stringify(paymentData, null, 2));
    console.log('Received signature:', receivedSignature);
    
    // CRITICAL: Verify IPN signature for security
    if (process.env.NOWPAYMENTS_IPN_SECRET) {
      const crypto = require('crypto');
      
      // Sort the parameters by keys and convert to JSON string
      const sortedParams = JSON.stringify(paymentData, Object.keys(paymentData).sort());
      
      // Create HMAC signature with sha512
      const expectedSignature = crypto
        .createHmac('sha512', process.env.NOWPAYMENTS_IPN_SECRET)
        .update(sortedParams)
        .digest('hex');
      
      console.log('Expected signature:', expectedSignature);
      
      // Verify signature matches
      if (receivedSignature !== expectedSignature) {
        console.error('Invalid IPN signature! Possible fraud attempt.');
        return res.status(401).json({ error: 'Invalid signature' });
      }
      
      console.log('✅ IPN signature verified successfully');
    } else {
      console.warn('⚠️ WARNING: IPN_SECRET not set - skipping signature verification');
    }
    
    // Find transaction by payment ID or invoice ID
    let transaction = await Transaction.findOne({ 
      $or: [
        { paymentId: paymentData.payment_id },
        { invoiceId: paymentData.invoice_id },
        { paymentId: paymentData.invoice_id }
      ]
    });
    
    if (!transaction) {
      console.log('Transaction not found for payment:', paymentData.payment_id || paymentData.invoice_id);
      return res.status(404).json({ error: 'Transaction not found' });
    }
    
    // Update transaction status based on payment status
    const oldStatus = transaction.status;
    transaction.status = paymentData.payment_status;
    
    console.log(`Payment ${paymentData.payment_id} status: ${oldStatus} -> ${paymentData.payment_status}`);
    
    // Handle successful payment (finished status)
    if (paymentData.payment_status === 'finished') {
      transaction.status = 'completed';
      transaction.completedAt = new Date();
      
      // Store additional payment details
      if (paymentData.outcome_amount) {
        transaction.payAmount = paymentData.outcome_amount.toString();
      }
      if (paymentData.actually_paid) {
        transaction.payAmount = paymentData.actually_paid.toString();
      }
      
      await transaction.save();
      
      // Get user
      const user = await User.findById(transaction.userId);
      
      if (user && oldStatus !== 'completed') {
        // Add to balance (only if not already completed)
        user.balance += transaction.amount;
        user.totalDeposited += transaction.amount;
        await user.save();
        
        console.log(`✅ Added ${transaction.amount} to user ${user.email} balance`);
        
        // Create investment
        const plans = {
          gold: { roi: 30 },
          silver: { roi: 50 },
          platinum: { roi: 90 }
        };
        
        // Get plan from transaction
        const plan = transaction.plan || 'gold';
        
        const roi = plans[plan].roi;
        const dailyReturn = (transaction.amount * (roi / 100)) / 30;
        const maturityDate = new Date();
        maturityDate.setDate(maturityDate.getDate() + 30);
        
        const investment = new Investment({
          userId: user._id,
          plan,
          amount: transaction.amount,
          initialAmount: transaction.amount,
          roi,
          dailyReturn,
          maturityDate
        });
        
        await investment.save();
        
        console.log('✅ Investment created successfully for user:', user.email);
      }
    } 
    // Handle partially paid status
    else if (paymentData.payment_status === 'partially_paid') {
      transaction.status = 'partially_paid';
      await transaction.save();
      console.log(`⚠️ Payment ${paymentData.payment_id} partially paid`);
    }
    // Handle failed/expired/refunded statuses
    else if (paymentData.payment_status === 'failed' || 
             paymentData.payment_status === 'expired' || 
             paymentData.payment_status === 'refunded') {
      transaction.status = 'failed';
      await transaction.save();
      console.log(`❌ Payment ${paymentData.payment_id} ${paymentData.payment_status}`);
    } 
    // Handle intermediate statuses (waiting, confirming, confirmed, sending)
    else {
      await transaction.save();
      console.log(`🔄 Payment ${paymentData.payment_id} status: ${paymentData.payment_status}`);
    }
    
    // IMPORTANT: Always return 200 OK to acknowledge receipt
    res.status(200).json({ success: true });
  } catch (error) {
    console.error('❌ Webhook error:', error);
    // Still return 200 to prevent NowPayments from retrying
    res.status(200).json({ error: 'Webhook processing failed' });
  }
});

// ==================== ADMIN ROUTES ====================

// Get all users
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const users = await User.find().select('-password').sort({ createdAt: -1 });
    res.json({ users });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Get all investments
app.get('/api/admin/investments', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const investments = await Investment.find()
      .populate('userId', 'name email')
      .sort({ createdAt: -1 });
    res.json({ investments });
  } catch (error) {
    console.error('Get investments error:', error);
    res.status(500).json({ error: 'Failed to fetch investments' });
  }
});

// Get all transactions
app.get('/api/admin/transactions', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const transactions = await Transaction.find()
      .populate('userId', 'name email')
      .sort({ createdAt: -1 });
    res.json({ transactions });
  } catch (error) {
    console.error('Get transactions error:', error);
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

// Update user balance
app.post('/api/admin/users/:id/balance', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { amount, type } = req.body;
    
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    if (type === 'add') {
      user.balance += amount;
    } else if (type === 'deduct') {
      if (user.balance < amount) {
        return res.status(400).json({ error: 'Insufficient balance' });
      }
      user.balance -= amount;
    }
    
    await user.save();
    
    const transaction = new Transaction({
      userId: user._id,
      type: type === 'add' ? 'bonus' : 'withdrawal',
      amount,
      status: 'completed',
      description: `Admin ${type} balance`,
      completedAt: new Date()
    });
    
    await transaction.save();
    
    res.json({ message: 'Balance updated successfully', user });
  } catch (error) {
    console.error('Update balance error:', error);
    res.status(500).json({ error: 'Failed to update balance' });
  }
});

// Process withdrawal (admin)
app.post('/api/admin/transactions/:id/process', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { status, txHash } = req.body;
    
    const transaction = await Transaction.findById(req.params.id);
    if (!transaction) {
      return res.status(404).json({ error: 'Transaction not found' });
    }
    
    if (transaction.type !== 'withdrawal') {
      return res.status(400).json({ error: 'Not a withdrawal transaction' });
    }
    
    transaction.status = status;
    transaction.txHash = txHash;
    
    if (status === 'completed') {
      transaction.completedAt = new Date();
      
      const user = await User.findById(transaction.userId);
      if (user) {
        user.totalWithdrawn += transaction.amount;
        await user.save();
      }
    } else if (status === 'cancelled') {
      const user = await User.findById(transaction.userId);
      if (user) {
        user.balance += transaction.amount;
        await user.save();
      }
    }
    
    await transaction.save();
    
    res.json({ message: 'Transaction processed successfully', transaction });
  } catch (error) {
    console.error('Process transaction error:', error);
    res.status(500).json({ error: 'Failed to process transaction' });
  }
});

// Suspend/Activate user
app.post('/api/admin/users/:id/status', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { status } = req.body;
    
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    user.status = status;
    await user.save();
    
    res.json({ message: 'User status updated successfully', user });
  } catch (error) {
    console.error('Update user status error:', error);
    res.status(500).json({ error: 'Failed to update user status' });
  }
});

// Get dashboard stats
app.get('/api/admin/stats', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const activeUsers = await User.countDocuments({ status: 'active' });
    const totalInvestments = await Investment.countDocuments({ status: 'active' });
    
    const investmentStats = await Investment.aggregate([
      { $match: { status: 'active' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    
    const totalInvested = investmentStats.length > 0 ? investmentStats[0].total : 0;
    
    const withdrawalStats = await Transaction.aggregate([
      { $match: { type: 'withdrawal', status: 'pending' } },
      { $group: { _id: null, total: { $sum: '$amount' }, count: { $sum: 1 } } }
    ]);
    
    const pendingWithdrawals = withdrawalStats.length > 0 ? withdrawalStats[0].count : 0;
    const pendingAmount = withdrawalStats.length > 0 ? withdrawalStats[0].total : 0;
    
    res.json({
      totalUsers,
      activeUsers,
      totalInvestments,
      totalInvested,
      pendingWithdrawals,
      pendingAmount
    });
  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// ==================== CRON JOB - Update Investments ====================

const updateDailyReturns = async () => {
  try {
    const activeInvestments = await Investment.find({ status: 'active' });
    
    for (const investment of activeInvestments) {
      const daysSinceUpdate = Math.floor((Date.now() - investment.lastUpdated) / (1000 * 60 * 60 * 24));
      
      if (daysSinceUpdate >= 1) {
        investment.daysElapsed += daysSinceUpdate;
        investment.amount += investment.dailyReturn * daysSinceUpdate;
        investment.lastUpdated = new Date();
        
        const user = await User.findById(investment.userId);
        if (user) {
          user.balance += investment.dailyReturn * daysSinceUpdate;
          await user.save();
        }
        
        const transaction = new Transaction({
          userId: investment.userId,
          type: 'profit',
          amount: investment.dailyReturn * daysSinceUpdate,
          status: 'completed',
          description: `Daily profit from ${investment.plan} investment`,
          completedAt: new Date()
        });
        await transaction.save();
        
        if (investment.daysElapsed >= 30) {
          investment.status = 'completed';
        }
        
        await investment.save();
      }
    }
    
    console.log('✅ Daily returns updated');
  } catch (error) {
    console.error('❌ Update daily returns error:', error);
  }
};

// Run daily returns update every hour
setInterval(updateDailyReturns, 60 * 60 * 1000);

// Initial update on startup
setTimeout(updateDailyReturns, 5000);

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});