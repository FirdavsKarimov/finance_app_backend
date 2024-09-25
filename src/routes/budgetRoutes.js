const express = require('express');
const budgetController = require('../controllers/budgetController');
const authMiddleware = require('../middleware/authMiddleware');

const router = express.Router();

router.use(authMiddleware);

router.post('/', budgetController.createBudget);
router.get('/', budgetController.getBudgets);

module.exports = router;
