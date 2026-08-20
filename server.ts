import express, { Request, Response } from 'express';
import path from 'path';
import fs from 'fs';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { createServer as createViteServer } from 'vite';
import { checkVpnAndProxy, inspectIp, extractClientIp } from './server/vpnDetector';
import { sendUserStatusEmail } from './server/emailService';

const app = express();
const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'taskpoint-super-secret-key-2026';

app.use(express.json({ limit: '20mb' }));

// File-based persistence storage path
const DATA_DIR = path.join(process.cwd(), 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// Initial Database Schema Structure
interface DatabaseSchema {
  users: any[];
  tasks: any[];
  submissions: any[];
  withdrawals: any[];
  notifications: any[];
  tickets: any[];
  disputes: any[];
  referralLogs: any[];
  pointTransactions: any[];
  bookmarks: any[];
  announcements: any[];
  vpnLogs?: any[];
  emailLogs?: any[];
  settings: any;
}

// Helper to Load DB
function loadDB(): DatabaseSchema {
  let dbData: DatabaseSchema;
  if (!fs.existsSync(DB_FILE)) {
    dbData = generateSeedData();
    fs.writeFileSync(DB_FILE, JSON.stringify(dbData, null, 2));
  } else {
    try {
      const content = fs.readFileSync(DB_FILE, 'utf-8');
      dbData = JSON.parse(content);
    } catch (err) {
      console.error('Error reading db.json, re-initializing...', err);
      dbData = generateSeedData();
      fs.writeFileSync(DB_FILE, JSON.stringify(dbData, null, 2));
    }
  }
  ensureDemoAccountsExist(dbData);
  return dbData;
}

function ensureDemoAccountsExist(db: DatabaseSchema) {
  let changed = false;

  // Clean up any previously soft-deleted users
  if (db.users && db.users.some(u => u.isDeleted)) {
    db.users = db.users.filter(u => !u.isDeleted);
    changed = true;
  }

  if (!db.vpnLogs) {
    db.vpnLogs = [];
    changed = true;
  }

  // 1. Primary ADMIN Account (Always ensure admin can log in)
  let admin = db.users.find(u => u.role === 'ADMIN' || u.email?.toLowerCase() === 'emma1854986@gmail.com');
  if (!admin) {
    admin = {
      id: 'usr-admin-01',
      email: 'emma1854986@gmail.com',
      username: 'TaskPointAdmin',
      passwordHash: bcrypt.hashSync('Admin123!', 10),
      role: 'ADMIN',
      avatar: 'https://api.dicebear.com/7.x/bottts/svg?seed=TaskPointAdmin',
      country: 'Nigeria',
      isEmailVerified: true,
      isBanned: false,
      availableBalance: 0.0,
      pendingBalance: 0.0,
      totalWithdrawn: 0.0,
      airdropPoints: 0,
      referralPoints: 0,
      dailyStreak: 1,
      referralCode: 'ADMINREF',
      createdAt: new Date().toISOString(),
      lastLoginAt: new Date().toISOString(),
    };
    db.users.push(admin);
    changed = true;
  }

  // Ensure system settings defaults
  if (!db.settings) {
    db.settings = {
      websiteName: 'TaskPoint',
      minWithdrawalUSD: 5.0,
      referralPointsBonus: 20,
      maintenanceMode: false,
      supportEmail: 'support@taskpoint.app',
      strictVpnBlocking: true,
      blockDataCenters: true,
      vpnWhitelistedIps: [],
    };
    changed = true;
  } else {
    if (db.settings.referralPointsBonus === 100 || db.settings.referralPointsBonus === 10) {
      db.settings.referralPointsBonus = 20;
      changed = true;
    }
    if (db.settings.strictVpnBlocking === undefined) {
      db.settings.strictVpnBlocking = true;
      changed = true;
    }
    if (db.settings.blockDataCenters === undefined) {
      db.settings.blockDataCenters = true;
      changed = true;
    }
    if (!db.settings.vpnWhitelistedIps) {
      db.settings.vpnWhitelistedIps = [];
      changed = true;
    }
  }

  if (changed) {
    try {
      fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
    } catch (err) {
      console.error('Error saving db.json in ensureDemoAccountsExist:', err);
    }
  }
}

// Helper to Save DB
function saveDB(data: DatabaseSchema) {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
  } catch (err) {
    console.error('Error saving db.json:', err);
  }
}

// Seed Generator with clean default structure (no dummy tasks, submissions, withdrawals, or fake users)
function generateSeedData(): DatabaseSchema {
  const adminPassword = bcrypt.hashSync('Admin123!', 10);

  const users = [
    {
      id: 'usr-admin-01',
      email: 'emma1854986@gmail.com',
      username: 'TaskPointAdmin',
      passwordHash: adminPassword,
      role: 'ADMIN',
      avatar: 'https://api.dicebear.com/7.x/bottts/svg?seed=TaskPointAdmin',
      country: 'Nigeria',
      isEmailVerified: true,
      isBanned: false,
      availableBalance: 0.0,
      pendingBalance: 0.0,
      totalWithdrawn: 0.0,
      airdropPoints: 0,
      referralPoints: 0,
      dailyStreak: 0,
      referralCode: 'ADMINREF',
      createdAt: new Date().toISOString(),
      lastLoginAt: new Date().toISOString(),
    }
  ];

  const tasks: any[] = [];
  const submissions: any[] = [];
  const withdrawals: any[] = [];
  const notifications: any[] = [];
  const tickets: any[] = [];
  const disputes: any[] = [];
  const referralLogs: any[] = [];
  const pointTransactions: any[] = [];
  const announcements: any[] = [];

  const settings = {
    websiteName: 'TaskPoint',
    minWithdrawalUSD: 5.0,
    referralPointsBonus: 20,
    maintenanceMode: false,
    supportEmail: 'support@taskpoint.app',
  };

  return {
    users,
    tasks,
    submissions,
    withdrawals,
    notifications,
    tickets,
    disputes,
    referralLogs,
    pointTransactions,
    bookmarks: [],
    announcements,
    settings,
  };
}

// Authentication Middleware
function authenticateToken(req: Request & { user?: any }, res: Response, next: any) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  jwt.verify(token, JWT_SECRET, (err: any, decoded: any) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired session token' });
    }
    const db = loadDB();
    const user = db.users.find((u) => u.id === decoded.id);
    if (!user) {
      return res.status(401).json({ error: 'Account no longer exists' });
    }
    if (user.isDeleted) {
      return res.status(403).json({ error: 'This account has been deleted by an administrator. Please contact support.' });
    }
    if (user.isBanned) {
      return res.status(403).json({ error: 'Account banned. Please contact support if you think it was a mistake' });
    }
    req.user = user;
    next();
  });
}

// Optional Auth Helper
function getAuthenticatedUser(req: Request): any | null {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return null;
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return null;
  }
}

// Strict Proxy & VPN Guard Enforcement Helper
async function enforceVpnCheck(
  req: Request,
  res: Response,
  action: 'LOGIN' | 'REGISTER' | 'GOOGLE_AUTH' | 'SUBMISSION' | 'WITHDRAWAL' | 'BONUS_CLAIM',
  usernameOrEmail?: string
): Promise<{ allowed: boolean; vpnResult?: any }> {
  const db = loadDB();
  const settings = db.settings || {};

  // Designated Super Admin bypass
  const cleanTarget = (usernameOrEmail || '').trim().toLowerCase();
  if (cleanTarget === 'emma1854986@gmail.com' || cleanTarget === 'taskpointadmin') {
    return { allowed: true };
  }

  const vpnResult = await checkVpnAndProxy(req, settings);

  if (vpnResult.isBlocked) {
    const logEntry = {
      id: 'vpn-' + Date.now() + '-' + Math.random().toString(36).substr(2, 5),
      ip: vpnResult.ip,
      action,
      usernameOrEmail: usernameOrEmail || 'Unknown',
      country: vpnResult.country,
      countryCode: vpnResult.countryCode,
      city: vpnResult.city,
      isp: vpnResult.isp,
      org: vpnResult.org,
      reason: vpnResult.reason,
      detectedHeaders: vpnResult.detectedHeaders,
      createdAt: new Date().toISOString(),
    };

    if (!db.vpnLogs) db.vpnLogs = [];
    db.vpnLogs.unshift(logEntry);
    if (db.vpnLogs.length > 500) db.vpnLogs = db.vpnLogs.slice(0, 500);
    saveDB(db);

    res.status(403).json({
      error: 'Access Denied: VPN or Proxy detected. TaskPoint strictly prohibits the use of VPNs, Proxies, or Datacenter networks to maintain fair microtask validation and prevent fraudulent activity. Please disconnect your VPN/Proxy and try again.',
      isVpn: true,
      vpnDetails: {
        ip: vpnResult.ip,
        country: vpnResult.country,
        isp: vpnResult.isp,
        threatScore: vpnResult.threatScore,
        reason: vpnResult.reason,
      },
    });
    return { allowed: false, vpnResult };
  }

  return { allowed: true, vpnResult };
}

// REST API ROUTES

// --- AUTH ROUTES ---

// 1. Google Authentication (Sign In & Sign Up without email/password)
app.post('/api/auth/google', async (req, res) => {
  try {
    const { email, displayName, photoURL, uid, referralCode } = req.body || {};
    const cleanEmail = (email || '').trim().toLowerCase();

    if (!cleanEmail) {
      return res.status(400).json({ error: 'Google email is required for authentication' });
    }

    // Strict Proxy & VPN Check
    const vpnCheck = await enforceVpnCheck(req, res, 'GOOGLE_AUTH', cleanEmail);
    if (!vpnCheck.allowed) return;

    const db = loadDB();
    if (!db.users) db.users = [];
    if (!db.referralLogs) db.referralLogs = [];
    if (!db.pointTransactions) db.pointTransactions = [];
    if (!db.notifications) db.notifications = [];

    let user = db.users.find(
      (u) => (u.email && u.email.toLowerCase() === cleanEmail) || (uid && (u as any).googleUid === uid)
    );

    if (user) {
      // Existing user login
      if (user.isDeleted) {
        return res.status(403).json({ error: 'This account has been deleted by an administrator. Please contact support.' });
      }
      if (user.isBanned) {
        return res.status(403).json({ error: 'Account banned. Please contact support if you think it was a mistake' });
      }

      user.lastLoginAt = new Date().toISOString();
      user.isEmailVerified = true;
      if (photoURL && (!user.avatar || user.avatar.includes('dicebear'))) {
        user.avatar = photoURL;
      }
      if (uid && !(user as any).googleUid) {
        (user as any).googleUid = uid;
      }
      saveDB(db);

      const token = jwt.sign(
        { id: user.id, email: user.email, username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      const { passwordHash: _, ...safeUser } = user;
      return res.json({
        token,
        user: safeUser,
        message: `Welcome back, ${user.username}!`,
      });
    }

    // New User Registration with Google
    let baseUsername = (displayName || cleanEmail.split('@')[0])
      .replace(/[^a-zA-Z0-9_]/g, '')
      .trim();
    if (!baseUsername || baseUsername.length < 2) {
      baseUsername = 'User' + Math.floor(1000 + Math.random() * 9000);
    }

    // Enforce strictly unique username across all users
    let finalUsername = baseUsername;
    let counter = 1;
    while (db.users.some((u) => u.username && u.username.toLowerCase() === finalUsername.toLowerCase())) {
      finalUsername = `${baseUsername}${counter}`;
      counter++;
    }

    let referrerId: string | undefined = undefined;
    if (referralCode) {
      const cleanRef = String(referralCode).trim().toUpperCase();
      const refUser = db.users.find((u) => u.referralCode && u.referralCode.toUpperCase() === cleanRef);
      if (refUser) {
        referrerId = refUser.id;
        const bonus = db.settings?.referralPointsBonus || 20;
        refUser.referralPoints = (refUser.referralPoints || 0) + bonus;
        refUser.airdropPoints = (refUser.airdropPoints || 0) + bonus;
        refUser.referralCount = (refUser.referralCount || 0) + 1;

        db.referralLogs.push({
          id: 'ref-' + Date.now(),
          referrerId: refUser.id,
          referredUsername: finalUsername,
          pointsAwarded: bonus,
          ruleTriggered: 'REGISTRATION',
          createdAt: new Date().toISOString(),
        });

        db.pointTransactions.push({
          id: 'pt-' + Date.now(),
          userId: refUser.id,
          amount: bonus,
          type: 'REFERRAL_BONUS',
          description: `Earned +${bonus} XP for inviting @${finalUsername}`,
          createdAt: new Date().toISOString(),
        });

        db.notifications.push({
          id: 'notif-' + Date.now(),
          userId: refUser.id,
          title: 'Referral Bonus Received! 🎁',
          message: `You earned +${bonus} XP for inviting @${finalUsername}!`,
          type: 'REFERRAL',
          isRead: false,
          createdAt: new Date().toISOString(),
        });
      }
    }

    const newReferralCode = finalUsername.toUpperCase().slice(0, 5) + Math.floor(100 + Math.random() * 900);

    const detectedCountry = vpnCheck.vpnResult?.country && !['Local', 'Unknown', 'XX'].includes(vpnCheck.vpnResult.country)
      ? vpnCheck.vpnResult.country
      : 'Global';

    const newUser = {
      id: 'usr-' + Date.now(),
      email: cleanEmail,
      username: finalUsername,
      passwordHash: '',
      googleUid: uid || undefined,
      role: cleanEmail === 'emma1854986@gmail.com' ? 'ADMIN' : 'USER',
      avatar: photoURL || `https://api.dicebear.com/7.x/bottts/svg?seed=${finalUsername}`,
      country: detectedCountry,
      isEmailVerified: true,
      isBanned: false,
      availableBalance: 0.0,
      pendingBalance: 0.0,
      totalWithdrawn: 0.0,
      airdropPoints: 20, // 20 XP welcome bonus
      referralPoints: 0,
      dailyStreak: 1,
      referralCode: newReferralCode,
      referredById: referrerId,
      createdAt: new Date().toISOString(),
      lastLoginAt: new Date().toISOString(),
    };

    db.users.push(newUser);
    saveDB(db);

    const token = jwt.sign(
      { id: newUser.id, email: newUser.email, username: newUser.username, role: newUser.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    const { passwordHash: _, ...safeUser } = newUser;
    return res.json({
      token,
      user: safeUser,
      message: `Welcome to TaskPoint, @${finalUsername}! +20 XP Welcome Bonus credited.`,
    });
  } catch (err: any) {
    console.error('Error during Google authentication:', err);
    return res.status(500).json({ error: err.message || 'An unexpected error occurred during Google authentication. Please try again.' });
  }
});

// 1. Register (Direct Account Creation)
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password, referralCode } = req.body;
  const cleanUsername = (username || '').trim();
  const cleanEmail = (email || '').trim().toLowerCase();
  const cleanPassword = (password || '').trim();

  if (!cleanUsername || !cleanEmail || !cleanPassword) {
    return res.status(400).json({ error: 'Username, email and password are required' });
  }

  if (cleanUsername.length < 3 || cleanUsername.length > 25 || !/^[a-zA-Z0-9_]+$/.test(cleanUsername)) {
    return res.status(400).json({ error: 'Username must be between 3 and 25 characters and contain only letters, numbers, and underscores.' });
  }

  if (cleanPassword.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters long' });
  }

  // Strict Proxy & VPN Check
  const vpnCheck = await enforceVpnCheck(req, res, 'REGISTER', cleanUsername || cleanEmail);
  if (!vpnCheck.allowed) return;

  const db = loadDB();
  
  // Check if username is already taken by any other user (case-insensitive)
  const usernameExists = db.users.some(
    (u) => u.username.toLowerCase() === cleanUsername.toLowerCase()
  );
  if (usernameExists) {
    return res.status(400).json({ error: `Username "@${cleanUsername}" is already in use. Please choose another unique username.` });
  }

  const existingEmailUser = db.users.find(
    (u) => u.email.toLowerCase() === cleanEmail
  );
  if (existingEmailUser) {
    if (existingEmailUser.isDeleted) {
      return res.status(403).json({ error: 'This account was deleted by an administrator. Please contact support to appeal.' });
    }
    if (existingEmailUser.isBanned) {
      return res.status(403).json({ error: 'Account banned. Please contact support if you think it was a mistake' });
    }
    return res.status(400).json({ error: 'An account with this email address is already registered.' });
  }

  const passwordHash = bcrypt.hashSync(cleanPassword, 10);

  let referrerId: string | undefined = undefined;
  if (referralCode) {
    const cleanRef = String(referralCode).trim();
    const refUser = db.users.find((u) => u.referralCode === cleanRef);
    if (refUser) {
      referrerId = refUser.id;
      const bonus = db.settings.referralPointsBonus || 20;
      refUser.referralPoints = (refUser.referralPoints || 0) + bonus;
      refUser.airdropPoints = (refUser.airdropPoints || 0) + bonus;
      refUser.referralCount = (refUser.referralCount || 0) + 1;

      db.referralLogs.push({
        id: 'ref-' + Date.now(),
        referrerId: refUser.id,
        referredUsername: cleanUsername,
        pointsAwarded: bonus,
        ruleTriggered: 'REGISTRATION',
        createdAt: new Date().toISOString(),
      });

      db.pointTransactions.push({
        id: 'pt-' + Date.now(),
        userId: refUser.id,
        amount: bonus,
        type: 'REFERRAL_BONUS',
        description: `Earned +${bonus} XP for inviting user ${cleanUsername}`,
        createdAt: new Date().toISOString(),
      });

      db.notifications.push({
        id: 'notif-' + Date.now(),
        userId: refUser.id,
        title: 'Referral Bonus Received! 🎁',
        message: `You earned +${bonus} XP for inviting @${cleanUsername}!`,
        type: 'REFERRAL',
        isRead: false,
        createdAt: new Date().toISOString(),
      });
    }
  }

  const newReferralCode = cleanUsername.toUpperCase().slice(0, 5) + Math.floor(100 + Math.random() * 900);

  const detectedCountry = vpnCheck.vpnResult?.country && !['Local', 'Unknown', 'XX'].includes(vpnCheck.vpnResult.country)
    ? vpnCheck.vpnResult.country
    : 'Nigeria';

  const newUser = {
    id: 'usr-' + Date.now(),
    email: cleanEmail,
    username: cleanUsername,
    passwordHash,
    role: cleanEmail === 'emma1854986@gmail.com' ? 'ADMIN' : 'USER',
    avatar: `https://api.dicebear.com/7.x/bottts/svg?seed=${cleanUsername}`,
    country: detectedCountry,
    isEmailVerified: true,
    isBanned: false,
    availableBalance: 0.0,
    pendingBalance: 0.0,
    totalWithdrawn: 0.0,
    airdropPoints: 20, // 20 XP welcome bonus
    referralPoints: 0,
    dailyStreak: 1,
    referralCode: newReferralCode,
    referredById: referrerId,
    createdAt: new Date().toISOString(),
    lastLoginAt: new Date().toISOString(),
  };

  db.users.push(newUser);
  saveDB(db);

  const token = jwt.sign(
    { id: newUser.id, email: newUser.email, username: newUser.username, role: newUser.role },
    JWT_SECRET,
    { expiresIn: '7d' }
  );

  const { passwordHash: _, ...safeUser } = newUser;
  return res.json({
    token,
    user: safeUser,
    message: 'Account created successfully!',
  });
});

// 2. Login (Direct Authentication)
app.post('/api/auth/login', async (req, res) => {
  const { emailOrUsername, password } = req.body;
  const identifier = (emailOrUsername || '').trim().toLowerCase();
  const pass = (password || '').trim();

  if (!identifier || !pass) {
    return res.status(400).json({ error: 'Please enter your username/email and password' });
  }

  // Strict Proxy & VPN Check
  const vpnCheck = await enforceVpnCheck(req, res, 'LOGIN', identifier);
  if (!vpnCheck.allowed) return;

  const db = loadDB();
  const user = db.users.find(
    (u) =>
      u.email.toLowerCase() === identifier ||
      u.username.toLowerCase() === identifier
  );

  if (!user) {
    return res.status(400).json({ error: 'Invalid credentials. Please check your username/email and password.' });
  }

  if (user.isDeleted) {
    return res.status(403).json({ error: 'This account has been deleted by an administrator. Please contact support for restoration.' });
  }

  if (user.isBanned) {
    return res.status(403).json({ error: 'Account banned. Please contact support if you think it was a mistake' });
  }

  const isMatch = bcrypt.compareSync(pass, user.passwordHash);
  if (!isMatch) {
    return res.status(400).json({ error: 'Invalid credentials. Please check your password.' });
  }

  user.lastLoginAt = new Date().toISOString();
  user.isEmailVerified = true;
  saveDB(db);

  const token = jwt.sign(
    { id: user.id, email: user.email, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '7d' }
  );

  const { passwordHash: _, ...safeUser } = user;
  return res.json({
    token,
    user: safeUser,
    message: 'Logged in successfully!',
  });
});

// 3. Forgot / Reset Password
app.post('/api/auth/forgot-password', (req, res) => {
  const { email, newPassword } = req.body;
  const targetEmail = (email || '').trim().toLowerCase();
  const pass = (newPassword || '').trim();

  if (!targetEmail) {
    return res.status(400).json({ error: 'Email address is required' });
  }

  if (!pass || pass.length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters long' });
  }

  const db = loadDB();
  const user = db.users.find((u) => u.email.toLowerCase() === targetEmail);

  if (!user) {
    return res.status(404).json({ error: 'No account found with this email address.' });
  }

  if (user.isDeleted) {
    return res.status(403).json({ error: 'This account has been deleted by an administrator. Please contact support.' });
  }

  if (user.isBanned) {
    return res.status(403).json({ error: 'Account banned. Please contact support if you think it was a mistake' });
  }

  user.passwordHash = bcrypt.hashSync(pass, 10);
  user.isEmailVerified = true;
  saveDB(db);

  const token = jwt.sign(
    { id: user.id, email: user.email, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '7d' }
  );

  const { passwordHash: _, ...safeUser } = user;
  return res.json({
    token,
    user: safeUser,
    message: 'Password updated successfully! You are now logged in.',
  });
});

app.get('/api/auth/me', authenticateToken, (req: any, res) => {
  const db = loadDB();
  const user = db.users.find((u) => u.id === req.user.id);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  const { passwordHash: _, ...safeUser } = user;
  return res.json({ user: safeUser });
});

app.post('/api/auth/streak-claim', authenticateToken, (req: any, res) => {
  const db = loadDB();
  const user = db.users.find((u) => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (user.isRestricted) {
    return res.status(403).json({ error: 'Your account is currently restricted from claiming daily streak bonuses.' });
  }

  const todayStr = new Date().toISOString().split('T')[0];

  if (user.lastStreakClaimDate === todayStr) {
    return res.status(400).json({ error: 'You have already claimed your daily streak bonus today! Please check back tomorrow.' });
  }

  const yesterdayDate = new Date(Date.now() - 86400000);
  const yesterdayStr = yesterdayDate.toISOString().split('T')[0];

  if (user.lastStreakClaimDate === yesterdayStr) {
    user.dailyStreak = (user.dailyStreak || 0) + 1;
  } else {
    // Missed a day or first claim
    user.dailyStreak = 1;
  }

  user.lastStreakClaimDate = todayStr;
  const streakBonus = 10;
  user.airdropPoints = (user.airdropPoints || 0) + streakBonus;

  db.pointTransactions.push({
    id: 'pt-' + Date.now(),
    userId: user.id,
    amount: streakBonus,
    type: 'DAILY_STREAK',
    description: `Claimed Day ${user.dailyStreak} streak bonus (+${streakBonus} XP)`,
    createdAt: new Date().toISOString(),
  });

  saveDB(db);
  const { passwordHash: _, ...safeUser } = user;
  return res.json({ user: safeUser, bonusPoints: streakBonus });
});

// --- TASKS ENDPOINTS ---
app.get('/api/tasks', (req, res) => {
  const { category, search, difficulty } = req.query;
  const authUser = getAuthenticatedUser(req);
  const db = loadDB();

  let filtered = db.tasks.filter((t) => t.status === 'ACTIVE');

  if (category && category !== 'ALL') {
    filtered = filtered.filter((t) => t.category === category);
  }
  if (difficulty && difficulty !== 'ALL') {
    filtered = filtered.filter((t) => t.difficulty === difficulty);
  }
  if (search) {
    const q = (search as string).toLowerCase();
    filtered = filtered.filter(
      (t) => t.title.toLowerCase().includes(q) || t.description.toLowerCase().includes(q)
    );
  }

  // Attach submission status and bookmark if user is logged in
  const mapped = filtered.map((task) => {
    let userSubmissionStatus = undefined;
    let isBookmarked = false;
    if (authUser) {
      const sub = db.submissions.find((s) => s.taskId === task.id && s.userId === authUser.id);
      if (sub) userSubmissionStatus = sub.status;

      isBookmarked = db.bookmarks.some((b) => b.taskId === task.id && b.userId === authUser.id);
    }
    return {
      ...task,
      userSubmissionStatus,
      isBookmarked,
    };
  });

  return res.json(mapped);
});

app.post('/api/tasks/bookmark', authenticateToken, (req: any, res) => {
  const { taskId } = req.body;
  const db = loadDB();
  const index = db.bookmarks.findIndex((b) => b.taskId === taskId && b.userId === req.user.id);
  let isBookmarked = false;

  if (index >= 0) {
    db.bookmarks.splice(index, 1);
    isBookmarked = false;
  } else {
    db.bookmarks.push({
      id: 'bm-' + Date.now(),
      taskId,
      userId: req.user.id,
      createdAt: new Date().toISOString(),
    });
    isBookmarked = true;
  }
  saveDB(db);
  return res.json({ isBookmarked });
});

// --- TASK SUBMISSIONS ENDPOINTS ---
app.post('/api/submissions', authenticateToken, (req: any, res) => {
  const { taskId, proofScreenshot, proofScreenshot2, proofText, proofUrl, proofUsername } = req.body;
  const db = loadDB();

  const task = db.tasks.find((t) => t.id === taskId);
  if (!task) return res.status(404).json({ error: 'Task not found' });

  const user = db.users.find((u) => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (user.isRestricted) {
    return res.status(403).json({ error: 'Your account is currently restricted from submitting task proofs.' });
  }

  if (task.totalSlots > 0 && task.totalSlots < 999999 && task.filledSlots >= task.totalSlots) {
    return res.status(400).json({ error: 'Task is fully completed! No slots remaining.' });
  }

  const existing = db.submissions.find((s) => s.taskId === taskId && s.userId === req.user.id);
  if (existing) {
    return res.status(400).json({ error: 'You have already submitted proof for this task!' });
  }

  const newSubmission = {
    id: 'sub-' + Date.now(),
    taskId,
    userId: user.id,
    proofScreenshot: proofScreenshot || null,
    proofScreenshot2: proofScreenshot2 || null,
    proofText: proofText || null,
    proofUrl: proofUrl || null,
    proofUsername: proofUsername || null,
    status: 'PENDING',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  db.submissions.push(newSubmission);
  user.pendingBalance += task.rewardCash;
  task.filledSlots += 1;

  saveDB(db);
  return res.json({ message: 'Submission uploaded successfully!', submission: newSubmission });
});

app.get('/api/submissions/my', authenticateToken, (req: any, res) => {
  const db = loadDB();
  const mySubmissions = db.submissions.filter((s) => s.userId === req.user.id);

  const populated = mySubmissions.map((s) => {
    const task = db.tasks.find((t) => t.id === s.taskId);
    const dispute = db.disputes.find((d) => d.submissionId === s.id);
    return {
      ...s,
      taskTitle: task?.title || 'Unknown Task',
      taskCategory: task?.category,
      rewardCash: task?.rewardCash,
      rewardPoints: task?.rewardPoints,
      dispute,
    };
  });

  return res.json(populated);
});

// --- WALLET & WITHDRAWALS ---
app.post('/api/user/wallet-address', authenticateToken, (req: any, res) => {
  const { address, network } = req.body;
  const db = loadDB();
  const user = db.users.find((u) => u.id === req.user.id);

  if (!user) return res.status(404).json({ error: 'User not found' });

  const cleanAddress = (address || '').trim();
  const cleanNetwork = network === 'SOL' ? 'SOL' : 'TRC';

  if (!cleanAddress) {
    return res.status(400).json({ error: 'Please enter a valid wallet address.' });
  }

  // Rule: Must not have "sol" or "trc" inside the address string
  if (/(sol|trc)/i.test(cleanAddress)) {
    return res.status(400).json({ 
      error: 'Wallet address must not contain network labels like "sol" or "trc". Please enter the pure blockchain address only.' 
    });
  }

  if (cleanNetwork === 'TRC') {
    if (!cleanAddress.startsWith('T') || cleanAddress.length < 30 || cleanAddress.length > 36) {
      return res.status(400).json({ 
        error: 'Invalid TRC20 address format. TRC20 USDT addresses must start with "T" (approx. 34 characters).' 
      });
    }
  } else if (cleanNetwork === 'SOL') {
    if (cleanAddress.length < 32 || cleanAddress.length > 44 || !/^[1-9A-HJ-NP-za-km-z]+$/.test(cleanAddress)) {
      return res.status(400).json({ 
        error: 'Invalid Solana (SOL) address format. Must be a valid Base58 public key.' 
      });
    }
  }

  // Permanently save on user account
  user.savedWalletAddress = cleanAddress;
  user.savedWalletNetwork = cleanNetwork;
  saveDB(db);

  const { passwordHash: _, ...safeUser } = user;
  return res.json({ 
    message: `USDT (${cleanNetwork}) wallet address saved permanently to your account!`, 
    user: safeUser 
  });
});

app.get('/api/wallet/history', authenticateToken, (req: any, res) => {
  const db = loadDB();
  const userWithdrawals = db.withdrawals.filter((w) => w.userId === req.user.id);
  return res.json(userWithdrawals);
});

app.post('/api/wallet/withdraw', authenticateToken, (req: any, res) => {
  const { amount, currency, method, details } = req.body;
  const db = loadDB();
  const user = db.users.find((u) => u.id === req.user.id);

  if (!user) return res.status(404).json({ error: 'User not found' });

  if (!user.savedWalletAddress) {
    return res.status(400).json({ 
      error: 'Please add and save your USDT (TRC20 or SOL) wallet address before requesting a withdrawal.' 
    });
  }

  if (user.isRestricted) {
    return res.status(403).json({ error: 'Your account is currently restricted from requesting payouts.' });
  }

  const minAmount = db.settings.minWithdrawalUSD || 5.0;
  if (amount < minAmount) {
    return res.status(400).json({ error: `Minimum withdrawal amount is $${minAmount.toFixed(2)} USD` });
  }

  if (user.availableBalance < amount) {
    return res.status(400).json({ error: 'Insufficient available balance' });
  }

  // Deduct available balance and hold
  user.availableBalance -= amount;

  const withdrawalDetails = details || `USDT (${user.savedWalletNetwork || 'TRC20'}): ${user.savedWalletAddress}`;

  const newWithdrawal = {
    id: 'wd-' + Date.now(),
    userId: user.id,
    amount,
    currency: currency || 'USDT',
    method: method || 'USDT',
    details: withdrawalDetails,
    status: 'PENDING',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  db.withdrawals.push(newWithdrawal);

  db.notifications.push({
    id: 'notif-' + Date.now(),
    userId: user.id,
    title: 'Withdrawal Requested 💸',
    message: `Your payout request of $${amount.toFixed(2)} USDT is queued for Wednesday disbursement!`,
    type: 'WITHDRAWAL',
    isRead: false,
    createdAt: new Date().toISOString(),
  });

  saveDB(db);
  return res.json({ 
    message: 'Withdrawal requested successfully! Payment will be sent Wednesday.', 
    withdrawal: newWithdrawal 
  });
});

// --- REFERRALS & LEADERBOARD ---
app.get('/api/referrals/my', authenticateToken, (req: any, res) => {
  const db = loadDB();
  const user = db.users.find((u) => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const logs = db.referralLogs.filter((r) => r.referrerId === user.id);
  const referredUsers = db.users
    .filter((u) => u.referredById === user.id)
    .map((u) => ({
      username: u.username,
      avatar: u.avatar,
      createdAt: u.createdAt,
      airdropPoints: u.airdropPoints,
    }));

  return res.json({
    referralCode: user.referralCode,
    referralPoints: user.referralPoints,
    totalReferrals: referredUsers.length,
    history: logs,
    referredUsers,
    bonusPerReferral: db.settings.referralPointsBonus || 20,
  });
});

const GLOBAL_SEED_LEADERBOARD: any[] = [];

app.get('/api/leaderboard', (req, res) => {
  const { type = 'POINTS' } = req.query; // POINTS, EARNERS, REFERRALS
  const db = loadDB();

  // Combine DB users with global seed earners
  const realUserEntries = db.users.map((u) => {
    const cashEarned = (u.availableBalance || 0) + (u.totalWithdrawn || 0);
    const referralCount = db.users.filter((x) => x.referredById === u.id).length;
    const referralPoints = u.referralPoints !== undefined && u.referralPoints !== null ? u.referralPoints : (referralCount * 20);
    const earnedTaskXP = u.airdropPoints || 0;
    const totalAirdropXP = earnedTaskXP + referralPoints;

    return {
      userId: u.id,
      username: u.username,
      avatar: u.avatar || `https://api.dicebear.com/7.x/bottts/svg?seed=${u.username}`,
      country: u.country || 'Global',
      cashEarned,
      earnedTaskXP,
      airdropPoints: totalAirdropXP, // Total Airdrop XP = Earned XP + Referral XP
      referralPoints,
      referralCount,
    };
  });

  const combined = [...realUserEntries];
  GLOBAL_SEED_LEADERBOARD.forEach((seed) => {
    if (!combined.some((item) => item.userId === seed.userId || item.username === seed.username)) {
      const earnedTaskXP = seed.taskPoints !== undefined ? seed.taskPoints : (seed.airdropPoints || 0);
      const referralPoints = seed.referralPoints || 0;
      const totalAirdropXP = earnedTaskXP + referralPoints;
      combined.push({
        ...seed,
        earnedTaskXP,
        referralPoints,
        airdropPoints: totalAirdropXP,
      });
    }
  });

  if (type === 'EARNERS') {
    combined.sort((a, b) => b.cashEarned - a.cashEarned);
  } else if (type === 'REFERRALS') {
    combined.sort((a, b) => b.referralPoints - a.referralPoints);
  } else {
    // Default / POINTS: Rank by Total Airdrop XP (sum of earned task XP + referral XP)
    combined.sort((a, b) => b.airdropPoints - a.airdropPoints);
  }

  const leaderboard = combined.slice(0, 20).map((u, idx) => {
    let primaryValue = u.airdropPoints;
    if (type === 'EARNERS') primaryValue = u.cashEarned;
    if (type === 'REFERRALS') primaryValue = u.referralPoints;

    return {
      rank: idx + 1,
      userId: u.userId,
      username: u.username,
      avatar: u.avatar,
      country: u.country,
      value: primaryValue,
      cashEarned: u.cashEarned,
      airdropPoints: u.airdropPoints, // Total Airdrop XP
      earnedTaskXP: u.earnedTaskXP || 0,
      referralPoints: u.referralPoints,
      referralCount: u.referralCount,
      change: 0,
    };
  });

  return res.json(leaderboard);
});

// Airdrop Pool Statistics
app.get('/api/airdrop/stats', (req, res) => {
  const db = loadDB();
  const TOTAL_POOL_XP = 400000;

  // Real users: Task XP (airdropPoints) + Referral XP (referralPoints)
  const realUsersTaskXP = db.users.reduce((acc, u) => acc + (Number(u.airdropPoints) || 0), 0);
  const realUsersReferralXP = db.users.reduce((acc, u) => {
    const referralCount = db.users.filter((x) => x.referredById === u.id).length;
    const refPts = u.referralPoints !== undefined && u.referralPoints !== null ? Number(u.referralPoints) || 0 : (referralCount * 20);
    return acc + refPts;
  }, 0);

  // Seed users: Task XP + Referral XP
  const nonExistingSeed = GLOBAL_SEED_LEADERBOARD.filter(
    (seed) => !db.users.some((u) => u.id === seed.userId || u.username === seed.username)
  );
  const seedTaskXP = nonExistingSeed.reduce((acc, seed) => acc + (Number(seed.airdropPoints) || 0), 0);
  const seedReferralXP = nonExistingSeed.reduce((acc, seed) => acc + (Number(seed.referralPoints) || 0), 0);

  const totalTaskXP = realUsersTaskXP + seedTaskXP;
  const totalReferralXP = realUsersReferralXP + seedReferralXP;
  const totalClaimedXP = totalTaskXP + totalReferralXP;
  const availableToClaimXP = Math.max(0, TOTAL_POOL_XP - totalClaimedXP);

  return res.json({
    totalPoolXP: TOTAL_POOL_XP,
    totalClaimedXP,
    availableToClaimXP,
    totalTaskXP,
    totalReferralXP,
  });
});

function purgeExpiredClosedTickets(db: DatabaseSchema): boolean {
  if (!db.tickets || !Array.isArray(db.tickets)) return false;
  const now = Date.now();
  const SEVENTY_TWO_HOURS_MS = 72 * 60 * 60 * 1000;
  
  const initialLength = db.tickets.length;
  db.tickets = db.tickets.filter((ticket) => {
    if (ticket.status === 'CLOSED') {
      const closedTimestamp = ticket.closedAt
        ? new Date(ticket.closedAt).getTime()
        : new Date(ticket.updatedAt).getTime();
      
      if (!isNaN(closedTimestamp) && (now - closedTimestamp >= SEVENTY_TWO_HOURS_MS)) {
        return false; // Purge/delete ticket after 72 hours
      }
    }
    return true;
  });

  return db.tickets.length !== initialLength;
}

// --- SUPPORT TICKETS ---
app.get('/api/support/tickets', authenticateToken, (req: any, res) => {
  const db = loadDB();
  if (purgeExpiredClosedTickets(db)) {
    saveDB(db);
  }
  const isAdmin = req.user.role === 'ADMIN' || req.user.role === 'SUPPORT' || req.user.role === 'MODERATOR';
  const tickets = isAdmin 
    ? [...db.tickets].sort((a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime())
    : db.tickets.filter((t) => t.userId === req.user.id).sort((a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime());
  return res.json(tickets);
});

app.put('/api/support/tickets/:id/status', authenticateToken, (req: any, res) => {
  const { status } = req.body;
  const db = loadDB();
  if (purgeExpiredClosedTickets(db)) {
    saveDB(db);
  }
  const ticket = db.tickets.find((t) => t.id === req.params.id);
  if (!ticket) return res.status(404).json({ error: 'Ticket not found' });

  const isAdmin = req.user.role === 'ADMIN' || req.user.role === 'SUPPORT' || req.user.role === 'MODERATOR';
  if (!isAdmin && ticket.userId !== req.user.id) {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  ticket.status = status;
  ticket.updatedAt = new Date().toISOString();
  if (status === 'CLOSED') {
    ticket.closedAt = new Date().toISOString();
  } else {
    delete ticket.closedAt;
  }

  if (isAdmin) {
    db.notifications.push({
      id: 'notif-' + Date.now(),
      userId: ticket.userId,
      title: 'Support Ticket Status Updated 🎟️',
      message: `Your ticket "${ticket.subject}" has been marked as ${status}.${status === 'CLOSED' ? ' Note: Closed tickets are automatically deleted after 72 hours.' : ''}`,
      type: 'SUPPORT',
      isRead: false,
      createdAt: new Date().toISOString(),
    });
  }

  saveDB(db);
  return res.json(ticket);
});

app.delete('/api/support/tickets/:id', authenticateToken, (req: any, res) => {
  const db = loadDB();
  const ticketIndex = db.tickets.findIndex((t) => t.id === req.params.id);
  if (ticketIndex === -1) return res.status(404).json({ error: 'Ticket not found' });

  const ticket = db.tickets[ticketIndex];
  const isAdmin = req.user.role === 'ADMIN' || req.user.role === 'SUPPORT' || req.user.role === 'MODERATOR';
  if (!isAdmin && ticket.userId !== req.user.id) {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  db.tickets.splice(ticketIndex, 1);
  saveDB(db);
  return res.json({ success: true, message: 'Ticket deleted successfully' });
});

// Public / Landing Page Support Ticket (No authentication required, username mandatory)
app.post('/api/support/public-ticket', (req, res) => {
  const { username, email, subject, category, priority, message } = req.body;
  const cleanUsername = (username || '').trim().replace(/^@/, '');
  const cleanSubject = (subject || '').trim();
  const cleanMessage = (message || '').trim();
  const cleanEmail = (email || '').trim().toLowerCase();

  if (!cleanUsername) {
    return res.status(400).json({ error: 'Please enter your username to submit a support ticket.' });
  }
  if (!cleanSubject) {
    return res.status(400).json({ error: 'Please provide a subject for your ticket.' });
  }
  if (!cleanMessage) {
    return res.status(400).json({ error: 'Please describe your inquiry or appeal in detail.' });
  }

  const db = loadDB();
  const matchedUser = db.users.find(
    (u) =>
      u.username.toLowerCase() === cleanUsername.toLowerCase() ||
      (cleanEmail && u.email.toLowerCase() === cleanEmail)
  );

  const ticketId = 'tkt-' + Date.now();
  const userId = matchedUser ? matchedUser.id : 'guest-' + Date.now();
  const finalUsername = matchedUser ? matchedUser.username : cleanUsername;
  const finalEmail = cleanEmail || (matchedUser ? matchedUser.email : undefined);

  const newTicket = {
    id: ticketId,
    userId,
    username: finalUsername,
    userEmail: finalEmail,
    subject: cleanSubject,
    category: category || (matchedUser?.isBanned ? 'Account Ban Appeal' : 'General'),
    priority: priority || (matchedUser?.isBanned ? 'HIGH' : 'MEDIUM'),
    status: 'OPEN',
    isGuest: !matchedUser,
    replies: [
      {
        id: 'rep-' + Date.now(),
        ticketId,
        userId,
        username: finalUsername,
        userAvatar: matchedUser?.avatar || `https://api.dicebear.com/7.x/bottts/svg?seed=${finalUsername}`,
        message: cleanMessage,
        isAdminReply: false,
        createdAt: new Date().toISOString(),
      },
    ],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  db.tickets.push(newTicket);
  saveDB(db);

  return res.json({
    success: true,
    ticket: newTicket,
    message: 'Support ticket submitted successfully. Our team will review your account.',
  });
});

app.post('/api/support/tickets', authenticateToken, (req: any, res) => {
  const { subject, category, priority, message } = req.body;
  const db = loadDB();
  const user = db.users.find((u) => u.id === req.user.id);

  const newTicket = {
    id: 'tkt-' + Date.now(),
    userId: req.user.id,
    username: user?.username,
    userEmail: user?.email,
    subject,
    category: category || 'General',
    priority: priority || 'MEDIUM',
    status: 'OPEN',
    replies: [
      {
        id: 'rep-' + Date.now(),
        ticketId: 'tkt-' + Date.now(),
        userId: req.user.id,
        username: user?.username || 'User',
        userAvatar: user?.avatar,
        message,
        isAdminReply: false,
        createdAt: new Date().toISOString(),
      },
    ],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  db.tickets.push(newTicket);
  saveDB(db);
  return res.json(newTicket);
});

app.post('/api/support/tickets/:id/reply', authenticateToken, (req: any, res) => {
  const { message } = req.body;
  const db = loadDB();
  const ticket = db.tickets.find((t) => t.id === req.params.id);
  if (!ticket) return res.status(404).json({ error: 'Ticket not found' });

  const user = db.users.find((u) => u.id === req.user.id);
  const isAdmin = req.user.role === 'ADMIN' || req.user.role === 'SUPPORT';

  ticket.replies.push({
    id: 'rep-' + Date.now(),
    ticketId: ticket.id,
    userId: req.user.id,
    username: user?.username || 'Support Agent',
    userAvatar: user?.avatar,
    message,
    isAdminReply: isAdmin,
    createdAt: new Date().toISOString(),
  });

  ticket.status = isAdmin ? 'IN_PROGRESS' : 'OPEN';
  ticket.updatedAt = new Date().toISOString();

  if (isAdmin) {
    db.notifications.push({
      id: 'notif-' + Date.now(),
      userId: ticket.userId,
      title: 'Support Reply Received 💬',
      message: `Support replied to ticket: "${ticket.subject}"`,
      type: 'SUPPORT',
      isRead: false,
      createdAt: new Date().toISOString(),
    });
  }

  saveDB(db);
  return res.json(ticket);
});

// --- DISPUTES ---
app.post('/api/disputes', authenticateToken, (req: any, res) => {
  const { submissionId, reason, additionalProof } = req.body;
  const db = loadDB();

  const user = db.users.find((u) => u.id === req.user.id);
  if (user?.isRestricted) {
    return res.status(403).json({ error: 'Your account is currently restricted from opening disputes.' });
  }

  const sub = db.submissions.find((s) => s.id === submissionId);
  if (!sub) return res.status(404).json({ error: 'Submission not found' });

  const existing = db.disputes.find((d) => d.submissionId === submissionId);
  if (existing) return res.status(400).json({ error: 'Dispute already opened for this submission' });

  const newDispute = {
    id: 'disp-' + Date.now(),
    submissionId,
    userId: req.user.id,
    username: user?.username,
    reason,
    additionalProof: additionalProof || null,
    status: 'PENDING',
    createdAt: new Date().toISOString(),
  };

  db.disputes.push(newDispute);
  saveDB(db);
  return res.json(newDispute);
});

// --- NOTIFICATIONS ---
app.get('/api/notifications', authenticateToken, (req: any, res) => {
  const db = loadDB();
  const myNotifs = db.notifications.filter((n) => n.userId === req.user.id);
  return res.json(myNotifs.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()));
});

app.put('/api/notifications/read-all', authenticateToken, (req: any, res) => {
  const db = loadDB();
  db.notifications.forEach((n) => {
    if (n.userId === req.user.id) n.isRead = true;
  });
  saveDB(db);
  return res.json({ success: true });
});

// --- ANNOUNCEMENTS ---
app.get('/api/announcements', (req, res) => {
  const db = loadDB();
  return res.json(db.announcements.filter((a) => a.isActive));
});

// --- ADMIN ENDPOINTS (Protected) ---
function requireAdmin(req: Request & { user?: any }, res: Response, next: any) {
  if (!req.user || (req.user.role !== 'ADMIN' && req.user.role !== 'MODERATOR' && req.user.role !== 'SUPPORT')) {
    return res.status(403).json({ error: 'Staff access privileges required' });
  }
  next();
}

function requireStrictAdmin(req: Request & { user?: any }, res: Response, next: any) {
  if (!req.user || req.user.role !== 'ADMIN') {
    return res.status(403).json({ error: 'Super administrator privileges required for this action' });
  }
  next();
}

app.get('/api/admin/stats', authenticateToken, requireAdmin, (req, res) => {
  const db = loadDB();

  const totalUsers = db.users.length;
  const activeUsers = db.users.filter((u) => !u.isBanned).length;
  const pendingSubmissions = db.submissions.filter((s) => s.status === 'PENDING').length;
  const pendingWithdrawals = db.withdrawals.filter((w) => w.status === 'PENDING').length;

  const todayStr = new Date().toISOString().split('T')[0];
  const todaySignups = db.users.filter((u) => u.createdAt && u.createdAt.startsWith(todayStr)).length;

  const approvedToday = db.submissions.filter(
    (s) => s.status === 'APPROVED' && s.updatedAt && s.updatedAt.startsWith(todayStr)
  ).length;

  const rejectedToday = db.submissions.filter(
    (s) => s.status === 'REJECTED' && s.updatedAt && s.updatedAt.startsWith(todayStr)
  ).length;

  const totalCashDistributed = db.users.reduce((acc, u) => {
    const withdrawn = Number(u.totalWithdrawn) || 0;
    const balance = Number(u.availableBalance) || 0;
    return acc + withdrawn + balance;
  }, 0);

  const totalPointsDistributed = db.users.reduce((acc, u) => {
    const taskPoints = Number(u.airdropPoints) || 0;
    const referralCount = db.users.filter((x) => x.referredById === u.id).length;
    const refPts = u.referralPoints !== undefined && u.referralPoints !== null ? Number(u.referralPoints) || 0 : (referralCount * 20);
    return acc + taskPoints + refPts;
  }, 0);

  const totalReferralPointsAwarded = db.users.reduce((acc, u) => {
    const refPts = Number(u.referralPoints) || 0;
    return acc + refPts;
  }, 0);

  // Generate 7-day activity metrics based on actual data
  const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  const dailyStats = days.map((date) => {
    return {
      date,
      users: totalUsers,
      tasks: db.submissions.length,
      payouts: totalCashDistributed,
    };
  });

  return res.json({
    totalUsers,
    activeUsers,
    todaySignups,
    pendingSubmissions,
    approvedToday,
    rejectedToday,
    pendingWithdrawals,
    totalCashDistributed,
    totalPointsDistributed,
    totalXpEarned: totalPointsDistributed,
    totalReferralPointsAwarded,
    dailyStats,
  });
});

// Admin Submissions List & Actions
app.get('/api/admin/submissions', authenticateToken, requireAdmin, (req, res) => {
  const db = loadDB();
  const populated = db.submissions.map((s) => {
    const task = db.tasks.find((t) => t.id === s.taskId);
    const user = db.users.find((u) => u.id === s.userId);
    return {
      ...s,
      taskTitle: task?.title || 'Unknown Task',
      taskCategory: task?.category,
      rewardCash: task?.rewardCash,
      rewardPoints: task?.rewardPoints,
      username: user?.username || 'Unknown User',
      userEmail: user?.email,
      userAvatar: user?.avatar,
    };
  });
  return res.json(populated);
});

app.put('/api/admin/submissions/:id', authenticateToken, requireAdmin, (req: any, res) => {
  const { status, adminComment } = req.body;
  const db = loadDB();
  const sub = db.submissions.find((s) => s.id === req.params.id);
  if (!sub) return res.status(404).json({ error: 'Submission not found' });

  const user = db.users.find((u) => u.id === sub.userId);
  const task = db.tasks.find((t) => t.id === sub.taskId);

  const prevStatus = sub.status;
  sub.status = status;
  sub.adminComment = adminComment || null;
  sub.updatedAt = new Date().toISOString();

  // If approving for the first time
  if (status === 'APPROVED' && prevStatus !== 'APPROVED') {
    if (user && task) {
      // Deduct pending balance and move to available balance
      user.pendingBalance = Math.max(0, user.pendingBalance - task.rewardCash);
      user.availableBalance += task.rewardCash;
      user.airdropPoints += task.rewardPoints;

      db.pointTransactions.push({
        id: 'pt-' + Date.now(),
        userId: user.id,
        amount: task.rewardPoints,
        type: 'TASK_REWARD',
        description: `Approved task: "${task.title}"`,
        createdAt: new Date().toISOString(),
      });

      db.notifications.push({
        id: 'notif-' + Date.now(),
        userId: user.id,
        title: 'Task Approved! 🟢',
        message: `Your task "${task.title}" was approved! $${task.rewardCash.toFixed(2)} + ${task.rewardPoints} Points added to your wallet!`,
        type: 'TASK',
        isRead: false,
        createdAt: new Date().toISOString(),
      });
    }
  } else if (status === 'REJECTED' && prevStatus === 'PENDING') {
    if (user && task) {
      user.pendingBalance = Math.max(0, user.pendingBalance - task.rewardCash);

      db.notifications.push({
        id: 'notif-' + Date.now(),
        userId: user.id,
        title: 'Task Submission Rejected 🔴',
        message: `Submission for "${task.title}" rejected. Reason: ${adminComment || 'Requirements not met'}. Click to dispute if this is an error.`,
        type: 'DISPUTE',
        isRead: false,
        createdAt: new Date().toISOString(),
      });
    }
  }

  saveDB(db);
  return res.json({ message: 'Submission updated', submission: sub });
});

// Admin Task CRUD
app.post('/api/admin/tasks', authenticateToken, requireAdmin, (req, res) => {
  const db = loadDB();
  const newTask = {
    id: 'task-' + Date.now(),
    ...req.body,
    filledSlots: 0,
    status: req.body.status || 'ACTIVE',
    createdAt: new Date().toISOString(),
  };
  db.tasks.push(newTask);
  saveDB(db);
  return res.json(newTask);
});

app.put('/api/admin/tasks/:id', authenticateToken, requireAdmin, (req, res) => {
  const db = loadDB();
  const taskIdx = db.tasks.findIndex((t) => t.id === req.params.id);
  if (taskIdx === -1) return res.status(404).json({ error: 'Task not found' });

  db.tasks[taskIdx] = {
    ...db.tasks[taskIdx],
    ...req.body,
    updatedAt: new Date().toISOString(),
  };
  saveDB(db);
  return res.json(db.tasks[taskIdx]);
});

app.delete('/api/admin/tasks/:id', authenticateToken, requireAdmin, (req, res) => {
  const db = loadDB();
  db.tasks = db.tasks.filter((t) => t.id !== req.params.id);
  saveDB(db);
  return res.json({ success: true });
});

// Admin Users Management
app.get('/api/admin/users', authenticateToken, requireAdmin, (req, res) => {
  const db = loadDB();
  const safeUsers = db.users.map(({ passwordHash, ...u }) => {
    const referralCount = db.users.filter((x) => x.referredById === u.id).length;
    const refPts = u.referralPoints !== undefined && u.referralPoints !== null ? Number(u.referralPoints) || 0 : (referralCount * 20);
    const taskXP = Number(u.airdropPoints) || 0;
    return {
      ...u,
      availableBalance: Number(u.availableBalance) || 0,
      airdropPoints: taskXP,
      referralPoints: refPts,
      referralCount,
    };
  });
  return res.json(safeUsers);
});

// Admin Add Support Account
app.post('/api/admin/users/support', authenticateToken, requireStrictAdmin, (req, res) => {
  const { username, email, password } = req.body;
  const cleanUsername = (username || '').trim();
  const cleanEmail = (email || '').trim().toLowerCase();

  if (!cleanUsername || !cleanEmail || !password) {
    return res.status(400).json({ error: 'Username, email, and password are required' });
  }

  if (cleanUsername.length < 3 || cleanUsername.length > 25 || !/^[a-zA-Z0-9_]+$/.test(cleanUsername)) {
    return res.status(400).json({ error: 'Username must be between 3 and 25 characters and contain only letters, numbers, and underscores.' });
  }

  const db = loadDB();
  const usernameTaken = db.users.some(
    (u) => u.username.toLowerCase() === cleanUsername.toLowerCase()
  );
  if (usernameTaken) {
    return res.status(400).json({ error: `Username "@${cleanUsername}" is already taken by another user. Please choose another username.` });
  }

  const emailTaken = db.users.some(
    (u) => u.email.toLowerCase() === cleanEmail
  );
  if (emailTaken) {
    return res.status(400).json({ error: 'Email address is already in use.' });
  }

  const salt = bcrypt.genSaltSync(10);
  const passwordHash = bcrypt.hashSync(password, salt);

  const newUser = {
    id: 'user-' + Date.now(),
    email: cleanEmail,
    username: cleanUsername,
    passwordHash,
    role: 'SUPPORT',
    country: 'Global Support',
    isEmailVerified: true,
    isBanned: false,
    isRestricted: false,
    isDeleted: false,
    availableBalance: 0,
    pendingBalance: 0,
    totalWithdrawn: 0,
    airdropPoints: 0,
    referralPoints: 0,
    dailyStreak: 0,
    referralCode: 'SUP' + Math.floor(1000 + Math.random() * 9000),
    createdAt: new Date().toISOString(),
  };

  db.users.push(newUser);
  saveDB(db);

  const { passwordHash: _, ...safeUser } = newUser;
  return res.json({ message: 'Support account created successfully', user: safeUser });
});

// Admin Update User Role (e.g., Promote to Support or Demote to User)
app.put('/api/admin/users/:id/role', authenticateToken, requireStrictAdmin, (req, res) => {
  const { role } = req.body;
  const db = loadDB();
  const user = db.users.find((u) => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (!['USER', 'SUPPORT', 'ADMIN', 'MODERATOR'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }

  user.role = role;
  saveDB(db);

  const { passwordHash: _, ...safeUser } = user;
  return res.json({ success: true, user: safeUser });
});

// Admin Update User Status (Ban / Restrict / Unban / Restore)
app.put('/api/admin/users/:id/status', authenticateToken, requireAdmin, async (req: any, res) => {
  const { isBanned, isRestricted, status, reason } = req.body;
  const db = loadDB();
  const user = db.users.find((u) => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const previousBanned = !!user.isBanned;
  const previousRestricted = !!user.isRestricted;
  let statusAction: 'BANNED' | 'RESTRICTED' | 'DELETED' | 'RESTORED' | null = null;

  if (status === 'BANNED') {
    user.isBanned = true;
    user.isRestricted = false;
    user.isDeleted = false;
    statusAction = 'BANNED';
  } else if (status === 'RESTRICTED') {
    user.isBanned = false;
    user.isRestricted = true;
    user.isDeleted = false;
    statusAction = 'RESTRICTED';
  } else if (status === 'ACTIVE' || status === 'RESTORE') {
    user.isBanned = false;
    user.isRestricted = false;
    user.isDeleted = false;
    delete user.deletedAt;
    delete user.deletedReason;
    statusAction = 'RESTORED';
  } else if (status === 'DELETED') {
    if (user.id === 'usr-admin-01') {
      return res.status(403).json({ error: 'The primary system administrator account cannot be deleted.' });
    }
    const targetEmail = user.email;
    const targetUsername = user.username;

    // Send email notification about deletion
    if (targetEmail) {
      sendUserStatusEmail({
        toEmail: targetEmail,
        username: targetUsername,
        action: 'DELETED',
        reason: reason?.trim() || undefined,
        adminName: req.user?.username || 'Administrator',
        timestamp: new Date().toISOString(),
      }).then((log) => {
        try {
          const freshDb = loadDB();
          if (!freshDb.emailLogs) freshDb.emailLogs = [];
          freshDb.emailLogs.unshift(log);
          saveDB(freshDb);
        } catch (e) {
          console.error('Failed to save email log', e);
        }
      }).catch(err => console.error('Email error:', err));
    }

    db.users = db.users.filter((u) => u.id !== req.params.id);
    if (db.submissions) db.submissions = db.submissions.filter((s) => s.userId !== req.params.id);
    if (db.withdrawals) db.withdrawals = db.withdrawals.filter((w) => w.userId !== req.params.id);
    if (db.tickets) db.tickets = db.tickets.filter((t) => t.userId !== req.params.id);
    if (db.disputes) db.disputes = db.disputes.filter((d) => d.userId !== req.params.id);
    if (db.notifications) db.notifications = db.notifications.filter((n) => n.userId !== req.params.id);
    saveDB(db);
    return res.json({ success: true, message: `Account @${targetUsername} deleted permanently. Email notification sent.` });
  } else {
    if (typeof isBanned === 'boolean') {
      user.isBanned = isBanned;
      if (isBanned) statusAction = 'BANNED';
      else if (previousBanned && !isBanned) statusAction = 'RESTORED';
    }
    if (typeof isRestricted === 'boolean') {
      user.isRestricted = isRestricted;
      if (isRestricted) statusAction = 'RESTRICTED';
      else if (previousRestricted && !isRestricted) statusAction = 'RESTORED';
    }
  }

  // Push in-app notification to target user
  let notifMsg = 'Your account status was updated by an administrator.';
  if (user.isDeleted) {
    notifMsg = `Your account has been DELETED by an administrator.${reason ? ` Reason: ${reason}` : ''}`;
  } else if (user.isBanned) {
    notifMsg = `Your account has been BANNED by an administrator.${reason ? ` Reason: ${reason}` : ''}`;
  } else if (user.isRestricted) {
    notifMsg = `Your account has been RESTRICTED. Submissions and payouts are temporarily disabled.${reason ? ` Reason: ${reason}` : ''}`;
  } else {
    notifMsg = 'Your account status has been set to ACTIVE. Full access restored.';
  }

  if (!db.notifications) db.notifications = [];
  db.notifications.push({
    id: 'notif-' + Date.now(),
    userId: user.id,
    title: user.isDeleted ? 'Account Deleted' : user.isBanned ? 'Account Banned' : user.isRestricted ? 'Account Restricted' : 'Account Reactivated',
    message: notifMsg,
    read: false,
    createdAt: new Date().toISOString(),
  });

  // Trigger Email Dispatch to User
  if (statusAction && user.email) {
    sendUserStatusEmail({
      toEmail: user.email,
      username: user.username,
      action: statusAction,
      reason: reason?.trim() || undefined,
      adminName: req.user?.username || 'Administrator',
      timestamp: new Date().toISOString(),
    }).then((log) => {
      try {
        const freshDb = loadDB();
        if (!freshDb.emailLogs) freshDb.emailLogs = [];
        freshDb.emailLogs.unshift(log);
        saveDB(freshDb);
      } catch (e) {
        console.error('Failed to record email log', e);
      }
    }).catch(err => console.error('Email sending error:', err));
  }

  saveDB(db);
  const { passwordHash: _, ...safeUser } = user;
  return res.json({ success: true, user: safeUser, emailNotification: `Email notice dispatched to ${user.email}` });
});

// Admin Restore User Account
app.post('/api/admin/users/:id/restore', authenticateToken, requireAdmin, (req: any, res) => {
  const db = loadDB();
  const user = db.users.find((u) => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  user.isDeleted = false;
  user.isBanned = false;
  user.isRestricted = false;
  delete user.deletedAt;
  delete user.deletedReason;

  if (!db.notifications) db.notifications = [];
  db.notifications.push({
    id: 'notif-' + Date.now(),
    userId: user.id,
    title: 'Account Restored! 🟢',
    message: 'Your account has been fully restored by an administrator. All account privileges are active.',
    read: false,
    createdAt: new Date().toISOString(),
  });

  // Dispatch Restored Email to User
  if (user.email) {
    sendUserStatusEmail({
      toEmail: user.email,
      username: user.username,
      action: 'RESTORED',
      adminName: req.user?.username || 'Administrator',
      timestamp: new Date().toISOString(),
    }).then((log) => {
      try {
        const freshDb = loadDB();
        if (!freshDb.emailLogs) freshDb.emailLogs = [];
        freshDb.emailLogs.unshift(log);
        saveDB(freshDb);
      } catch (e) {
        console.error('Failed to record email log', e);
      }
    }).catch(err => console.error('Email error on restore:', err));
  }

  saveDB(db);
  const { passwordHash: _, ...safeUser } = user;
  return res.json({ success: true, message: `Account @${user.username} restored to ACTIVE successfully! Email notice sent.`, user: safeUser });
});

// Admin Delete User / Support Account (Permanently removed from database and dashboard)
app.delete('/api/admin/users/:id', authenticateToken, requireAdmin, (req: any, res) => {
  const db = loadDB();
  const targetUser = db.users.find((u) => u.id === req.params.id);
  if (!targetUser) return res.status(404).json({ error: 'User not found' });

  // Protect the primary root admin account 'usr-admin-01' from being deleted
  if (targetUser.id === 'usr-admin-01') {
    return res.status(403).json({ error: 'The primary system administrator account cannot be deleted.' });
  }

  // Prevent an admin from deleting their own active logged-in account
  if (targetUser.id === req.user.id) {
    return res.status(403).json({ error: 'You cannot delete your own active admin session account.' });
  }

  const deletedUsername = targetUser.username;
  const deletedEmail = targetUser.email;
  const reason = req.body?.reason;

  // Dispatch Email Notification to user informing them of deletion
  if (deletedEmail) {
    sendUserStatusEmail({
      toEmail: deletedEmail,
      username: deletedUsername,
      action: 'DELETED',
      reason: reason?.trim() || undefined,
      adminName: req.user?.username || 'Administrator',
      timestamp: new Date().toISOString(),
    }).then((log) => {
      try {
        const freshDb = loadDB();
        if (!freshDb.emailLogs) freshDb.emailLogs = [];
        freshDb.emailLogs.unshift(log);
        saveDB(freshDb);
      } catch (e) {
        console.error('Failed to record email log', e);
      }
    }).catch(err => console.error('Email deletion notice error:', err));
  }

  // Permanently remove user from the system
  db.users = db.users.filter((u) => u.id !== req.params.id);
  if (db.submissions) db.submissions = db.submissions.filter((s) => s.userId !== req.params.id);
  if (db.withdrawals) db.withdrawals = db.withdrawals.filter((w) => w.userId !== req.params.id);
  if (db.tickets) db.tickets = db.tickets.filter((t) => t.userId !== req.params.id);
  if (db.disputes) db.disputes = db.disputes.filter((d) => d.userId !== req.params.id);
  if (db.notifications) db.notifications = db.notifications.filter((n) => n.userId !== req.params.id);

  saveDB(db);
  return res.json({ 
    success: true, 
    message: `Account @${deletedUsername} has been permanently deleted. An informational email has been sent to ${deletedEmail}.` 
  });
});

app.put('/api/admin/users/:id/adjust-balance', authenticateToken, requireStrictAdmin, (req, res) => {
  const { availableBalance, airdropPoints } = req.body;
  const db = loadDB();
  const user = db.users.find((u) => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (typeof availableBalance === 'number') user.availableBalance = availableBalance;
  if (typeof airdropPoints === 'number') user.airdropPoints = airdropPoints;

  saveDB(db);
  return res.json({ success: true, user });
});

// Admin Withdrawals Management
app.get('/api/admin/withdrawals', authenticateToken, requireStrictAdmin, (req, res) => {
  const db = loadDB();
  const populated = db.withdrawals.map((w) => {
    const user = db.users.find((u) => u.id === w.userId);
    return {
      ...w,
      username: user?.username || 'Unknown',
      userEmail: user?.email,
    };
  });
  return res.json(populated);
});

app.put('/api/admin/withdrawals/:id', authenticateToken, requireStrictAdmin, (req, res) => {
  const { status, paymentRef, adminNotes } = req.body;
  const db = loadDB();
  const w = db.withdrawals.find((item) => item.id === req.params.id);
  if (!w) return res.status(404).json({ error: 'Withdrawal not found' });

  const prevStatus = w.status;
  w.status = status;
  w.paymentRef = paymentRef || w.paymentRef;
  w.adminNotes = adminNotes || w.adminNotes;
  w.updatedAt = new Date().toISOString();

  const user = db.users.find((u) => u.id === w.userId);

  if (status === 'APPROVED' && prevStatus !== 'APPROVED' && user) {
    user.totalWithdrawn += w.amount;

    db.notifications.push({
      id: 'notif-' + Date.now(),
      userId: user.id,
      title: 'Withdrawal Approved! 💰',
      message: `Your payment of $${w.amount.toFixed(2)} USD has been processed! Ref: ${paymentRef || 'PAYOUT-OK'}`,
      type: 'WITHDRAWAL',
      isRead: false,
      createdAt: new Date().toISOString(),
    });
  } else if (status === 'REJECTED' && prevStatus === 'PENDING' && user) {
    // Refund balance back to available
    user.availableBalance += w.amount;

    db.notifications.push({
      id: 'notif-' + Date.now(),
      userId: user.id,
      title: 'Withdrawal Declined ❌',
      message: `Withdrawal request was declined and $${w.amount.toFixed(2)} USD returned to your available balance. Reason: ${adminNotes || 'Invalid account details'}`,
      type: 'WITHDRAWAL',
      isRead: false,
      createdAt: new Date().toISOString(),
    });
  }

  saveDB(db);
  return res.json({ message: 'Withdrawal updated', withdrawal: w });
});

// Admin Disputes
app.get('/api/admin/disputes', authenticateToken, requireAdmin, (req, res) => {
  const db = loadDB();
  const populated = db.disputes.map((d) => {
    const sub = db.submissions.find((s) => s.id === d.submissionId);
    const task = sub ? db.tasks.find((t) => t.id === sub.taskId) : null;
    const user = db.users.find((u) => u.id === d.userId);
    return {
      ...d,
      submission: sub,
      taskTitle: task?.title,
      rewardCash: task?.rewardCash,
      rewardPoints: task?.rewardPoints,
      username: user?.username,
    };
  });
  return res.json(populated);
});

app.put('/api/admin/disputes/:id', authenticateToken, requireAdmin, (req, res) => {
  const { status, adminComment } = req.body; // APPROVED or REJECTED
  const db = loadDB();
  const dispute = db.disputes.find((d) => d.id === req.params.id);
  if (!dispute) return res.status(404).json({ error: 'Dispute not found' });

  dispute.status = status;
  dispute.adminComment = adminComment;

  const sub = db.submissions.find((s) => s.id === dispute.submissionId);
  if (sub) {
    if (status === 'APPROVED') {
      sub.status = 'APPROVED';
      const user = db.users.find((u) => u.id === dispute.userId);
      const task = db.tasks.find((t) => t.id === sub.taskId);
      if (user && task) {
        user.availableBalance += task.rewardCash;
        user.airdropPoints += task.rewardPoints;

        db.notifications.push({
          id: 'notif-' + Date.now(),
          userId: user.id,
          title: 'Dispute Approved! 🎉',
          message: `Your dispute was reviewed and accepted! $${task.rewardCash.toFixed(2)} + ${task.rewardPoints} Points added to wallet.`,
          type: 'DISPUTE',
          isRead: false,
          createdAt: new Date().toISOString(),
        });
      }
    } else {
      db.notifications.push({
        id: 'notif-' + Date.now(),
        userId: dispute.userId,
        title: 'Dispute Decision ℹ️',
        message: `Your dispute review was finalized as REJECTED. Comment: ${adminComment || 'Original decision upheld.'}`,
        type: 'DISPUTE',
        isRead: false,
        createdAt: new Date().toISOString(),
      });
    }
  }

  saveDB(db);
  return res.json(dispute);
});

// Admin System Settings
app.get('/api/admin/settings', (req, res) => {
  const db = loadDB();
  return res.json(db.settings);
});

app.put('/api/admin/settings', authenticateToken, requireStrictAdmin, (req, res) => {
  const db = loadDB();
  db.settings = { ...db.settings, ...req.body };
  saveDB(db);
  return res.json(db.settings);
});

// --- VPN & PROXY SECURITY INTELLIGENCE ENDPOINTS ---

// Public/User Security Status Check
app.get('/api/security/my-ip', async (req, res) => {
  const db = loadDB();
  try {
    const check = await checkVpnAndProxy(req, db.settings || {});
    return res.json(check);
  } catch (err: any) {
    return res.status(500).json({ error: 'Failed to inspect connection', details: err.message });
  }
});

// Admin VPN / Proxy Block Logs
app.get('/api/admin/security/vpn-logs', authenticateToken, requireAdmin, (req, res) => {
  const db = loadDB();
  return res.json(db.vpnLogs || []);
});

// Admin Clear VPN Block Logs
app.delete('/api/admin/security/vpn-logs', authenticateToken, requireStrictAdmin, (req, res) => {
  const db = loadDB();
  db.vpnLogs = [];
  saveDB(db);
  return res.json({ success: true, message: 'VPN Block logs successfully cleared' });
});

// Admin Manual IP Inspector & Threat Analyzer
app.post('/api/admin/security/inspect-ip', authenticateToken, requireAdmin, async (req, res) => {
  const { ip } = req.body;
  if (!ip) {
    return res.status(400).json({ error: 'IP address is required for inspection' });
  }
  try {
    const result = await inspectIp(ip);
    return res.json(result);
  } catch (err: any) {
    return res.status(500).json({ error: 'Failed to analyze IP', details: err.message });
  }
});

// Admin Email Notification Audit Logs
app.get('/api/admin/security/email-logs', authenticateToken, requireAdmin, (req, res) => {
  const db = loadDB();
  return res.json(db.emailLogs || []);
});

// Admin Clear Email Notification Logs
app.delete('/api/admin/security/email-logs', authenticateToken, requireStrictAdmin, (req, res) => {
  const db = loadDB();
  db.emailLogs = [];
  saveDB(db);
  return res.json({ success: true, message: 'Email notification logs successfully cleared' });
});

// Announcements CRUD
app.post('/api/admin/announcements', authenticateToken, requireStrictAdmin, (req, res) => {
  const db = loadDB();
  const newAnc = {
    id: 'anc-' + Date.now(),
    ...req.body,
    isActive: true,
    createdAt: new Date().toISOString(),
  };
  db.announcements.push(newAnc);
  saveDB(db);
  return res.json(newAnc);
});

// SERVER STARTUP & VITE INTEGRATION
async function startServer() {
  // Vite Dev Server Middleware or Static Production
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: process.env.DISABLE_HMR === 'true' ? false : undefined,
        watch: process.env.DISABLE_HMR === 'true' ? null : {},
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`TaskPoint Fullstack Server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
