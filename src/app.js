const dotenv = require('dotenv');

const env = process?.env?.NODE_ENV || 'development';

switch (env) {
  case 'production':
    dotenv.config({ path: './.env.production' });
    break;
  case 'development':
    dotenv.config({ path: './.env.development' });
    break;
  default:
    dotenv.config();
}

const createError = require('http-errors');
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const passport = require('passport');
const session = require('express-session');
const csrf = require('csurf');
const flash = require('connect-flash');
const RedisStore = require('connect-redis').default;
const redis = require('redis');

const config = require('./config/config');
const connectDB = require('./db/db');
const passportConfig = require('./config/passport');

const redisClient = redis.createClient();
redisClient.connect().catch(console.error);

passportConfig(passport);

const indexRouter = require('./routes/index');
const expenseRoutes = require('./routes/expenseRoutes');
const budgetRoutes = require('./routes/budgetRoutes');
const authRoutes = require('./routes/authRoutes');

const app = express();

// Connect to MongoDB
connectDB()
  .then(() => console.log('Connected to MongoDB'))
  .catch((e) => console.error('Error connecting to MongoDB:', e));

app.use(helmet());

const corsOptions = {
  origin: config.CORS_ORIGIN,
  credentials: true,
  allowedHeaders: ['Content-Type', 'CSRF-Token', 'Authorization'],
};

app.use(cors(corsOptions));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
}));

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  store: new RedisStore({ client: redisClient }),
  secret: config.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production' },
}));

app.use(passport.initialize());
app.use(passport.session());

// CSRF protection
app.use(csrf({ cookie: true }));
app.use(flash());

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  return res.redirect('/auth/login');
}

// Routes
app.use('/', indexRouter);
app.use('/api/expenses', ensureAuthenticated, expenseRoutes);
app.use('/api/budgets', ensureAuthenticated, budgetRoutes);
app.use('/api/auth', authRoutes);

app.get('/get-csrf-token', (req, res) => {
  const token = req.csrfToken();
  req.session.csrfToken = token;
  res.json({ csrfToken: token });
});

app.post('/validate-csrf-token', (req, res) => {
  const csrfToken = req.headers['x-csrf-token'];

  if (!csrfToken || req.session.csrfToken !== csrfToken) {
    return res.status(403).json({ error: "Invalid CSRF token" });
  }

  res.json({ isValid: true });
});

app.get('/dashboard', ensureAuthenticated, (req, res) => {
  res.render('dashboard');
});

// catch 404 and forward to error handler
app.use((req, res, next) => {
  next(createError(404));
});

// error handler
app.use((err, req, res, next) => {
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
