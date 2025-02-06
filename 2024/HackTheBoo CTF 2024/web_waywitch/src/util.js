const jwt = require("jsonwebtoken");

function getUsernameFromToken(token) {
  const secret = "[REDACTED]";

  try {
    const decoded = jwt.verify(token, secret);
    return decoded.username;
  } catch (err) {
    throw new Error("Invalid token: " + err.message);
  }
}

module.exports = {
  getUsernameFromToken,
};
