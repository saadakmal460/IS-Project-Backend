const rateLimit = require('express-rate-limit');

// Apply rate limiting to ALL requests
const globalLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per window
  message: {
    status: 429,
    error: 'Too many requests, please try again later.',
  },
  standardHeaders: true, // Adds RateLimit-* headers
  legacyHeaders: false,  // Disable X-RateLimit-* headers
});


module.exports= {globalLimiter}
