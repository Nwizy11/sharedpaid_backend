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
  referralCode: { type: String, unique: true, sparse: true },
  referredBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  referralEarnings: { type: Number, default: 0 },
  totalReferrals: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

const referralSchema = new mongoose.Schema({
  referrer: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  referred: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  commission: { type: Number, default: 0 },
  totalEarned: { type: Number, default: 0 },
  status: { type: String, default: 'active', enum: ['active', 'inactive'] },
  createdAt: { type: Date, default: Date.now }
});

const Referral = mongoose.model('Referral', referralSchema);

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
  status: { 
    type: String, 
    default: 'pending', 
    enum: ['pending', 'completed', 'failed', 'cancelled', 'waiting', 'confirming', 'confirmed', 'sending', 'partially_paid', 'finished', 'expired'] 
  },
  paymentId: { type: String },
  payAddress: { type: String },
  payCurrency: { type: String, default: 'usdtbsc' },
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

// HELPER FUNCTION to generate unique referral code (after schemas)
const generateReferralCode = async () => {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let code = '';
  
  for (let i = 0; i < 8; i++) {
    code += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  
  // Check if code already exists
  const existing = await User.findOne({ referralCode: code });
  if (existing) {
    return generateReferralCode(); // Recursively try again
  }
  
  return code;
};

// NowPayments API Configuration
const NOWPAYMENTS_API_KEY = process.env.NOWPAYMENTS_API_KEY;
const NOWPAYMENTS_API_URL = 'https://api.nowpayments.io/v1';

const nowpaymentsRequest = async (endpoint, method = 'GET', data = null) => {
  try {
    const cleanEndpoint = endpoint.startsWith('/') ? endpoint.substring(1) : endpoint;
    const url = `${NOWPAYMENTS_API_URL}/${cleanEndpoint}`;
    
    console.log(`📤 ${method} ${url}`);
    
    const config = {
      method,
      url,
      headers: {
        'x-api-key': NOWPAYMENTS_API_KEY,
        'Content-Type': 'application/json'
      }
    };

    if (data) {
      config.data = data;
      console.log('📤 Data:', JSON.stringify(data, null, 2));
    }

    const response = await axios(config);
    console.log('📥 Response:', JSON.stringify(response.data, null, 2));
    
    return response.data;
  } catch (error) {
    console.error('❌ API Error:', error.response?.data || error.message);
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
    const { name, email, password, referralCode } = req.body; // Added referralCode
    
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Generate unique referral code for new user
    const newUserReferralCode = await generateReferralCode();
    
    const user = new User({
      name,
      email,
      password: hashedPassword,
      referralCode: newUserReferralCode
    });
    
    // Handle referral if code provided
    if (referralCode) {
      const referrer = await User.findOne({ referralCode: referralCode.toUpperCase() });
      if (referrer) {
        user.referredBy = referrer._id;
        await user.save();
        
        // Create referral relationship
        const referralRelation = new Referral({
          referrer: referrer._id,
          referred: user._id
        });
        await referralRelation.save();
        
        // Update referrer's total referrals
        referrer.totalReferrals += 1;
        await referrer.save();
        
        console.log(`✅ User ${user.email} referred by ${referrer.email}`);
      }
    } else {
      await user.save();
    }
    
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    
    res.status(201).json({
      message: 'Registration successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        balance: user.balance,
        isAdmin: user.isAdmin,
        referralCode: user.referralCode
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
      status: req.user.status,
      referralCode: req.user.referralCode,
      referralEarnings: req.user.referralEarnings,
      totalReferrals: req.user.totalReferrals
    }
  });
});

//ADD NEW ENDPOINT - Get User Referrals.
app.get('/api/referrals', authMiddleware, async (req, res) => {
  try {
    const referrals = await Referral.find({ referrer: req.user._id })
      .populate('referred', 'name email createdAt')
      .sort({ createdAt: -1 });
    
    res.json({ referrals });
  } catch (error) {
    console.error('Get referrals error:', error);
    res.status(500).json({ error: 'Failed to fetch referrals' });
  }
});

// ADD REFERRAL COMMISSION FUNCTION
const creditReferralCommission = async (userId, profitAmount) => {
  try {
    const user = await User.findById(userId);
    if (!user || !user.referredBy) return;
    
    const referrer = await User.findById(user.referredBy);
    if (!referrer) return;
    
    const commission = profitAmount * 0.10; // 10% commission
    
    // Credit referrer
    referrer.balance += commission;
    referrer.referralEarnings += commission;
    await referrer.save();
    
    // Update referral record
    await Referral.findOneAndUpdate(
      { referrer: referrer._id, referred: user._id },
      { 
        $inc: { 
          totalEarned: commission,
          commission: commission 
        }
      }
    );
    
    // Create transaction record
    const transaction = new Transaction({
      userId: referrer._id,
      type: 'bonus',
      amount: commission,
      status: 'completed',
      description: `Referral commission from ${user.name}`,
      completedAt: new Date()
    });
    await transaction.save();
    
    console.log(`✅ Referral commission: $${commission.toFixed(2)} to ${referrer.email} from ${user.email}`);
  } catch (error) {
    console.error('❌ Referral commission error:', error);
  }
};

// ==================== INVESTMENT ROUTES ====================
// Create investment - PAYMENT ONLY (NO INVOICE)
app.post('/api/investments/create', authMiddleware, async (req, res) => {
  try {
    const { plan, amount } = req.body;
    
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
    
    const orderId = `INV-${Date.now()}-${req.user._id}`;
    
    // console.log('='.repeat(80));
    // console.log('🚀 CREATING PAYMENT (NOT INVOICE)');
    // console.log('='.repeat(80));
    
    // STEP 1: Create payment with NowPayments
  const paymentRequestBody = {
  price_amount: amount,
  price_currency: 'usd',
  pay_currency: 'usdtbsc',  // ← CHANGED TO BEP20
  order_id: orderId,
  order_description: `${plan.toUpperCase()} Plan - $${amount}`
};
    
    console.log('📤 Request Body:', JSON.stringify(paymentRequestBody, null, 2));
    console.log('📤 Endpoint: POST https://api.nowpayments.io/v1/payment');
    
    // Make the API call
    const apiResponse = await axios({
      method: 'POST',
      url: 'https://api.nowpayments.io/v1/payment',
      headers: {
        'x-api-key': process.env.NOWPAYMENTS_API_KEY,
        'Content-Type': 'application/json'
      },
      data: paymentRequestBody
    });
    
    const paymentResponse = apiResponse.data;
    
    console.log('📥 API Response:', JSON.stringify(paymentResponse, null, 2));
    
    // Verify response has payment_id
    if (!paymentResponse || !paymentResponse.payment_id) {
      console.error('❌ NO PAYMENT_ID IN RESPONSE!');
      console.error('Response:', paymentResponse);
      throw new Error('Payment API did not return payment_id');
    }
    
    // Check if response has invoice fields (THIS SHOULD NOT HAPPEN)
    if (paymentResponse.invoice_id || paymentResponse.invoice_url) {
      console.error('❌ WRONG API ENDPOINT! Got invoice instead of payment!');
      console.error('Response has invoice_id:', paymentResponse.invoice_id);
      console.error('Response has invoice_url:', paymentResponse.invoice_url);
      throw new Error('API returned invoice instead of payment. Check API endpoint!');
    }
    
    console.log('✅ Payment ID received:', paymentResponse.payment_id);
    
    // STEP 2: Get payment details (pay_address might not be immediate)
    let paymentDetails = paymentResponse;
    let attempts = 0;
    const maxAttempts = 3;
    
    while (!paymentDetails.pay_address && attempts < maxAttempts) {
      attempts++;
      const waitTime = attempts * 2000; // 2s, 4s, 6s
      
      console.log(`⏳ Attempt ${attempts}/${maxAttempts}: Waiting ${waitTime}ms for pay_address...`);
      await new Promise(resolve => setTimeout(resolve, waitTime));
      
      console.log(`📤 Fetching payment status for: ${paymentResponse.payment_id}`);
      
      const statusResponse = await axios({
        method: 'GET',
        url: `https://api.nowpayments.io/v1/payment/${paymentResponse.payment_id}`,
        headers: {
          'x-api-key': process.env.NOWPAYMENTS_API_KEY
        }
      });
      
      paymentDetails = statusResponse.data;
      console.log(`📥 Status response (attempt ${attempts}):`, JSON.stringify(paymentDetails, null, 2));
      
      if (paymentDetails.pay_address) {
        console.log(`✅ Pay address found on attempt ${attempts}`);
        break;
      }
    }
    
    // Final check for pay_address
    if (!paymentDetails.pay_address) {
      console.error('❌ Pay address not generated after', maxAttempts, 'attempts');
      throw new Error('Payment address not available. Please try again in a moment.');
    }
    
    // Verify currency is USDT
    const currency = (paymentDetails.pay_currency || '').toLowerCase();
    if (!currency.includes('usdt')) {
      console.error('❌ Wrong currency:', paymentDetails.pay_currency);
      throw new Error(`Wrong currency: ${paymentDetails.pay_currency}. Expected USDTBSC.`);
    }
    
    // console.log('✅ Payment Details Verified:');
    // console.log('   Payment ID:', paymentDetails.payment_id);
    // console.log('   Pay Address:', paymentDetails.pay_address);
    // console.log('   Pay Amount:', paymentDetails.pay_amount);
    // console.log('   Pay Currency:', paymentDetails.pay_currency);
    // console.log('   Status:', paymentDetails.payment_status);
    
    // STEP 3: Save transaction to database
    const transaction = new Transaction({
      userId: req.user._id,
      type: 'deposit',
      amount,
      status: paymentDetails.payment_status || 'waiting',
      paymentId: paymentDetails.payment_id,
      payAddress: paymentDetails.pay_address,
      payCurrency: paymentDetails.pay_currency,
      payAmount: paymentDetails.pay_amount ? paymentDetails.pay_amount.toString() : null,
      priceAmount: amount,
      priceCurrency: 'usd',
      description: `${plan.toUpperCase()} Plan Investment`,
      plan
    });
    
    await transaction.save();
    
    console.log('✅ Transaction saved to database:', transaction._id);
    console.log('='.repeat(80));
    
    // STEP 4: Return payment details to frontend
    res.json({
      success: true,
      message: 'Payment created successfully',
      payment: {
        paymentId: paymentDetails.payment_id,
        payAddress: paymentDetails.pay_address,
        payAmount: paymentDetails.pay_amount,
        payCurrency: paymentDetails.pay_currency,
        paymentStatus: paymentDetails.payment_status,
        priceAmount: amount,
        priceCurrency: 'usd',
        network: 'TRC20',
        transactionId: transaction._id.toString()
      }
    });
    
  } catch (error) {
    console.error('❌ PAYMENT CREATION ERROR:');
    console.error('Error message:', error.message);
    console.error('Error response:', error.response?.data);
    console.error('Full error:', error);
    
    res.status(500).json({ 
      error: 'Failed to create payment',
      details: error.response?.data?.message || error.message
    });
  }
});
// // Helper function to verify nowpaymentsRequest is using correct base URL
// // Make sure your nowpaymentsRequest function uses: https://api.nowpayments.io
// function nowpaymentsRequest(endpoint, method = 'GET', data = null) {
//   const options = {
//     method,
//     headers: {
//       'x-api-key': process.env.NOWPAYMENTS_API_KEY,
//       'Content-Type': 'application/json'
//     }
//   };

//   if (data && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
//     options.body = JSON.stringify(data);
//   }

//   const url = `https://api.nowpayments.io${endpoint}`;
//   console.log(`Making request to: ${url}`);

//   return fetch(url, options)
//     .then(async response => {
//       const responseData = await response.json();
      
//       if (!response.ok) {
//         console.error('API Error Response:', responseData);
//         throw new Error(responseData.message || 'API request failed');
//       }
      
//       return responseData;
//     })
//     .catch(error => {
//       console.error('Request failed:', error);
//       throw error;
//     });
// }
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
app.post('/api/transactions/check-payment/:transactionId', authMiddleware, async (req, res) => {
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
        success: true,
        message: 'Payment already completed',
        status: 'completed'
      });
    }
    
    // Get payment status from NowPayments
    let paymentStatus;
    try {
      paymentStatus = await nowpaymentsRequest(`/payment/${transaction.paymentId}`);
    } catch (error) {
      return res.status(500).json({ error: 'Failed to fetch payment status from gateway' });
    }
    
    console.log('Payment status check:', paymentStatus);
    
    // Update transaction with latest status
    const oldStatus = transaction.status;
    transaction.status = paymentStatus.payment_status;
    
    // Handle completed payment
    if (paymentStatus.payment_status === 'finished') {
      transaction.status = 'completed';
      transaction.completedAt = new Date();
      
      if (paymentStatus.outcome_amount) {
        transaction.payAmount = paymentStatus.outcome_amount.toString();
      }
      
      await transaction.save();
      
      // Credit user balance (only if not already done)
      if (oldStatus !== 'completed') {
        const user = await User.findById(transaction.userId);
        if (user) {
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
          
          console.log('✅ Payment confirmed, balance credited, investment created');
          
          return res.json({
            success: true,
            message: 'Payment confirmed! Your investment is now active.',
            status: 'completed',
            investment
          });
        }
      }
    } else if (paymentStatus.payment_status === 'failed' || 
               paymentStatus.payment_status === 'expired') {
      transaction.status = 'failed';
      await transaction.save();
      return res.json({
        success: false,
        message: `Payment ${paymentStatus.payment_status}. Please try again.`,
        status: paymentStatus.payment_status
      });
    } else {
      // Still waiting/confirming
      await transaction.save();
      return res.json({
        success: false,
        message: `Payment status: ${paymentStatus.payment_status}. Waiting for confirmation...`,
        status: paymentStatus.payment_status
      });
    }
    
    res.json({ 
      success: true, 
      message: 'Status updated',
      status: transaction.status 
    });
    
  } catch (error) {
    console.error('Check payment error:', error);
    res.status(500).json({ 
      error: 'Failed to check payment status',
      details: error.response?.data?.message || error.message
    });
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
    
    console.log('📥 IPN:', paymentData.payment_id, paymentData.payment_status);
    
    const transaction = await Transaction.findOne({ 
      paymentId: paymentData.payment_id
    });
    
    if (!transaction) {
      return res.status(200).json({ message: 'Not found' });
    }
    
    const oldStatus = transaction.status;
    transaction.status = paymentData.payment_status;
    
    if (paymentData.outcome_amount) {
      transaction.payAmount = paymentData.outcome_amount.toString();
    }
    
    if (paymentData.payment_status === 'finished' && oldStatus !== 'completed') {
      transaction.status = 'completed';
      transaction.completedAt = new Date();
      await transaction.save();
      
      const user = await User.findById(transaction.userId);
      if (user) {
        user.balance += transaction.amount;
        user.totalDeposited += transaction.amount;
        await user.save();
        
        const plans = { gold: { roi: 30 }, silver: { roi: 50 }, platinum: { roi: 90 } };
        const roi = plans[transaction.plan || 'gold'].roi;
        const dailyReturn = (transaction.amount * (roi / 100)) / 30;
        const maturityDate = new Date();
        maturityDate.setDate(maturityDate.getDate() + 30);
        
        const investment = new Investment({
          userId: user._id,
          plan: transaction.plan || 'gold',
          amount: transaction.amount,
          initialAmount: transaction.amount,
          roi,
          dailyReturn,
          maturityDate
        });
        
        await investment.save();
        console.log('✅ Investment created');
      }
    } else {
      await transaction.save();
    }
    
    res.status(200).json({ success: true });
  } catch (error) {
    console.error('❌ Webhook error:', error);
    res.status(200).json({ error: 'Failed' });
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
        
        const profitAmount = investment.dailyReturn * daysSinceUpdate;
        
        const user = await User.findById(investment.userId);
        if (user) {
          user.balance += profitAmount;
          await user.save();
          
          // ADD THIS: Credit referral commission
          await creditReferralCommission(user._id, profitAmount);
        }
        
        const transaction = new Transaction({
          userId: investment.userId,
          type: 'profit',
          amount: profitAmount,
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