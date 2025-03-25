const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const userSchema = new mongoose.Schema({
  fullname: {
    firstname: {
      type: String,
      required: true,
      minlength: [3, "First name should be at least 3 characters long"],
    },
    lastname: {
      type: String,
      required: true,
      minlength: [3, "Last name should be at least 3 characters long"],
    },
  },
  email: {
    type: String,
    required: true,
    minlength: [5, `Email should be at least 5 characters long`],
  },
  password: {
    type: String,
    required: true,
    select: false,  // Ensure password is excluded by default
  },
  socketId: {
    type: String,
  },
});

// Generate Auth Token with Expiration
userSchema.methods.generateAuthToken = function () {
  const token = jwt.sign(
    { _id: this._id },
    process.env.JWT_SECRET_KEY,
    { expiresIn: "1h" }  // Added expiration time
  );
  return token;
};

// Compare Password (make sure to select +password when querying)
userSchema.methods.comparePassword = async function (password) {
  return await bcrypt.compare(password, this.password);
};

// Static method for password hashing
userSchema.statics.hashPassword = async function (password) {
  return await bcrypt.hash(password, 10);
};

const userModel = mongoose.model("user", userSchema);

module.exports = userModel;
