const Budget = require('../models/Budget');

exports.createBudget = async (req, res) => {
  try {
    const budget = new Budget({
      ...req.body,
      user: req.user._id
    });
    await budget.save();
    res.status(201).json(budget);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
};

exports.getBudgets = async (req, res) => {
  try {
    const budgets = await Budget.find({ user: req.user._id });
    res.json(budgets);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Add more controller methods as needed
